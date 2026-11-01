using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 – A04 Cryptographic Failures (CWE-916, CWE-327, CWE-321, CWE-329).
///
/// Dio A: registracija i prijava kupaca (lozinke "hashirane" MD5-om – vidi <see cref="Lab06Passwords"/>)
/// i javni "export" koji simulira procurjelu bazu (dump) – NAMJERNO bez autentikacije.
///
/// Dio B: pohrana brojeva kartica šifriranih AES/ECB-om s hardkodiranim ključem
/// (vidi <see cref="CardCrypto"/>).
/// </summary>
[ApiController]
[Route("api/lab06")]
public sealed class Lab06Controller(Db db) : ControllerBase
{
    private readonly CardCrypto _crypto = new();

    public sealed record Credentials(string? Username, string? Password);

    public sealed record CardRequest(string? CardNumber);

    // ----------------------------- Dio A: lozinke -----------------------------

    [HttpPost("register")]
    public IActionResult Register([FromBody] Credentials request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { error = "Nedostaje korisničko ime ili lozinka." });
        }

        var exists = Convert.ToInt64(db.Scalar(
            "SELECT COUNT(*) FROM lab06_customers WHERE username = $u", ("$u", request.Username)));
        if (exists > 0)
        {
            return Conflict(new { error = "Korisnik već postoji." });
        }

        db.Execute(
            "INSERT INTO lab06_customers (username, password_hash) VALUES ($u, $h)",
            ("$u", request.Username), ("$h", Lab06Passwords.Hash(request.Password)));
        return Ok(new { username = request.Username, status = "registriran" });
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] Credentials request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        var stored = db.Scalar(
            "SELECT password_hash FROM lab06_customers WHERE username = $u", ("$u", request.Username)) as string;
        if (stored is null || !Lab06Passwords.Verify(request.Password, stored))
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        return Ok(new { username = request.Username, status = "prijavljen" });
    }

    /// <summary>
    /// NAMJERNO bez autentikacije: simulira bazu lozinki koja je procurjela (npr. iz sigurnosne
    /// kopije). Pitanje vježbe nije "kako sakriti dump", nego "što napadač može s njim".
    /// </summary>
    [HttpGet("customers/export")]
    public IActionResult Export() =>
        Ok(db.Query("SELECT username, password_hash FROM lab06_customers ORDER BY username")
            .Select(r => new { username = r.GetString("username"), passwordHash = r.GetString("password_hash") }));

    // ----------------------------- Dio B: kartice -----------------------------

    [HttpPost("cards")]
    public IActionResult StoreCard([FromBody] CardRequest request)
    {
        var cardNumber = request.CardNumber?.Replace(" ", string.Empty);
        if (cardNumber is null || cardNumber.Length is < 12 or > 19 || !cardNumber.All(char.IsAsciiDigit))
        {
            return BadRequest(new { error = "Neispravan broj kartice." });
        }

        var ciphertext = _crypto.Encrypt(cardNumber);
        var id = db.Use(conn =>
        {
            using var insert = Db.CreateCommand(conn,
                "INSERT INTO lab06_cards (owner, ciphertext, last4) VALUES ('demo', $c, $l); SELECT last_insert_rowid();",
                ("$c", ciphertext), ("$l", cardNumber[^4..]));
            return Convert.ToInt64(insert.ExecuteScalar());
        });
        return Ok(new { id, ciphertext });
    }

    [HttpGet("cards")]
    public IActionResult ListCards() =>
        Ok(db.Query("SELECT id, ciphertext FROM lab06_cards ORDER BY id")
            .Select(r => new { id = r.GetInt64("id"), ciphertext = r.GetString("ciphertext") }));

    [HttpGet("cards/{id:long}/masked")]
    public IActionResult Masked(long id)
    {
        var last4 = db.Scalar("SELECT last4 FROM lab06_cards WHERE id = $id", ("$id", id)) as string;
        return last4 is null
            ? NotFound(new { error = "Kartica nije pronađena." })
            : Ok(new { id, masked = "**** **** **** " + last4 });
    }
}
