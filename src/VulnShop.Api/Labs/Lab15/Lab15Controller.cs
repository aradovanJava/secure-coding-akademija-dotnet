using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab15;

/// <summary>
/// Lab15 – A10 Mishandling of Exceptional Conditions (CWE-636, CWE-755, CWE-209, CWE-460).
///
/// ISPRAVLJENO:
///  (1) FAIL-CLOSED: svaka iznimka iz sigurnosne provjere (<see cref="LimitService.Check"/>) znači ODBIJANJE,
///  (2) validacija ulaza unaprijed (decimal, iznos &gt; 0, valuta s allowliste, različiti računi),
///  (3) terećenje i odobrenje u JEDNOJ transakciji (<c>SqliteTransaction</c>) – sve ili ništa,
///  (4) generičke poruke grešaka (ProblemDetails) s korelacijskim ID-om; detalji samo u logu.
/// </summary>
[ApiController]
[Route("api/lab15")]
[RequireAuth]
public sealed class Lab15Controller(Db db, LimitService limitService, ILogger<Lab15Controller> logger) : ControllerBase
{
    public sealed record TransferRequest(string? FromAccount, string? ToAccount, string? Amount, string? Currency);

    [HttpGet("accounts")]
    public IActionResult Accounts()
    {
        var user = HttpContext.RequireCurrentUser();
        var rows = db.Query(
            "SELECT account_no, balance FROM lab15_accounts WHERE owner_username = $u ORDER BY account_no",
            ("$u", user.Username));
        return Ok(rows.Select(r => new { accountNo = r.GetString("account_no"), balance = r.GetDecimal("balance") }));
    }

    [HttpPost("transfer")]
    public IActionResult Transfer([FromBody] TransferRequest request)
    {
        var user = HttpContext.RequireCurrentUser();

        // (2) Validacija ulaza unaprijed.
        if (string.IsNullOrWhiteSpace(request.FromAccount) || string.IsNullOrWhiteSpace(request.ToAccount) ||
            request.FromAccount == request.ToAccount ||
            !decimal.TryParse(request.Amount, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount) ||
            amount <= 0 || decimal.Round(amount, 2) != amount ||
            request.Currency is null || !LimitService.AllowedCurrencies.Contains(request.Currency))
        {
            return ProblemResult(StatusCodes.Status400BadRequest, "Neispravan zahtjev za transfer.");
        }

        // (1) FAIL-CLOSED: bilo kakva iznimka u sigurnosnoj provjeri = odbijanje.
        try
        {
            limitService.Check(amount, request.Currency);
        }
        catch (LimitExceededException)
        {
            return ProblemResult(StatusCodes.Status422UnprocessableEntity, "Iznos premašuje dnevni limit.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Provjera limita nije uspjela – transfer odbijen (fail-closed).");
            return ProblemResult(StatusCodes.Status400BadRequest, "Transfer nije dopušten.");
        }

        try
        {
            // (3) Terećenje i odobrenje u jednoj transakciji.
            return db.Use<IActionResult>(conn =>
            {
                using var tx = conn.BeginTransaction();

                var from = Db.QueryIn(conn, tx,
                    "SELECT balance FROM lab15_accounts WHERE account_no = $a AND owner_username = $o",
                    ("$a", request.FromAccount), ("$o", user.Username));
                var to = Db.QueryIn(conn, tx,
                    "SELECT balance FROM lab15_accounts WHERE account_no = $a", ("$a", request.ToAccount));
                if (from.Count == 0 || to.Count == 0)
                {
                    return ProblemResult(StatusCodes.Status404NotFound, "Račun nije pronađen.");
                }

                var fromBalance = from[0].GetDecimal("balance");
                if (fromBalance < amount)
                {
                    return ProblemResult(StatusCodes.Status422UnprocessableEntity, "Nedovoljno sredstava.");
                }

                Db.ExecuteIn(conn, tx, "UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                    ("$b", Money.ToDb(fromBalance - amount)), ("$a", request.FromAccount));
                Db.ExecuteIn(conn, tx, "UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                    ("$b", Money.ToDb(to[0].GetDecimal("balance") + amount)), ("$a", request.ToAccount));

                tx.Commit(); // bez Commit() se transakcija pri Dispose() poništava (rollback)
                return Ok(new { status = "izvršeno", amount, currency = request.Currency });
            });
        }
        catch (Exception ex)
        {
            // (4) Detalji samo u logu; klijent dobiva generičku poruku i korelacijski ID.
            logger.LogError(ex, "Transfer nije uspio, correlationId={CorrelationId}", HttpContext.TraceIdentifier);
            return ProblemResult(StatusCodes.Status500InternalServerError, "Transfer trenutačno nije moguć.");
        }
    }

    /// <summary>Generički ProblemDetails odgovor s korelacijskim ID-om (bez internih detalja).</summary>
    private ObjectResult ProblemResult(int status, string title)
    {
        var problem = new ProblemDetails { Status = status, Title = title };
        problem.Extensions["correlationId"] = HttpContext.TraceIdentifier;
        return new ObjectResult(problem) { StatusCode = status };
    }
}
