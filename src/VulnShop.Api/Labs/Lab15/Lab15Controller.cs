using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab15;

/// <summary>
/// Lab15 – A10 Mishandling of Exceptional Conditions (CWE-636, CWE-755, CWE-209, CWE-460).
///
/// RANJIVO:
///  (1) FAIL-OPEN: iznimka iz <see cref="LimitService.Check"/> se hvata i ignorira, pa transfer
///      s nepoznatom valutom (npr. XYZ) i iznosom iznad limita prolazi,
///  (2) NEMA TRANSAKCIJE: terećenje se izvrši, a ako odobrenje (uplata na nepostojeći račun)
///      ne uspije, novac nestaje,
///  (3) poruka greške vraća naziv klase iznimke i detalje (SQL, interni podaci).
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
        try
        {
            var amount = decimal.Parse(request.Amount!, NumberStyles.Number, CultureInfo.InvariantCulture);

            // RANJIVO (1) FAIL-OPEN: iznimka u sigurnosnoj provjeri se "proguta" i transfer se nastavlja.
            try
            {
                limitService.Check(amount, request.Currency);
            }
            catch (Exception ex)
            {
                logger.LogDebug("Provjera limita nije uspjela, nastavljam svejedno: {Message}", ex.Message);
            }

            // Terećenje računa pošiljatelja (samo vlastiti račun).
            var from = db.Query(
                "SELECT balance FROM lab15_accounts WHERE account_no = $a AND owner_username = $o",
                ("$a", request.FromAccount), ("$o", user.Username));
            if (from.Count == 0)
            {
                return NotFound(new { error = "Račun za terećenje nije pronađen." });
            }
            db.Execute("UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                ("$b", Money.ToDb(from[0].GetDecimal("balance") - amount)), ("$a", request.FromAccount));

            // RANJIVO (2): odobrenje je zasebna operacija, izvan transakcije s terećenjem.
            var to = db.Query("SELECT balance FROM lab15_accounts WHERE account_no = $a", ("$a", request.ToAccount));
            if (to.Count == 0)
            {
                // RANJIVO (2) + (3): terećenje se NE poništava, a poruka otkriva interne detalje (SQL, tablica).
                throw new InvalidOperationException(
                    "UPDATE lab15_accounts SET balance = balance + " + Money.ToDb(amount) +
                    " WHERE account_no = '" + request.ToAccount + "' -> 0 redaka (odredišni račun ne postoji)");
            }
            db.Execute("UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                ("$b", Money.ToDb(to[0].GetDecimal("balance") + amount)), ("$a", request.ToAccount));

            return Ok(new { status = "izvršeno", amount, currency = request.Currency });
        }
        catch (Exception ex)
        {
            // RANJIVO (3): vraća se puni naziv klase iznimke i detaljna poruka.
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { error = ex.GetType().FullName + ": " + ex.Message });
        }
    }
}
