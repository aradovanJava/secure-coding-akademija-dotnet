using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab11;

/// <summary>
/// Lab11 – A07 Authentication Failures: brute force i enumeracija korisnika (CWE-307, CWE-204).
///
/// RANJIVO:
///  - različiti odgovori za nepostojećeg korisnika (404 "Korisnik ne postoji.") i krivu lozinku
///    (401 "Pogrešna lozinka.") → napadač može utvrditi koja korisnička imena postoje (enumeracija),
///  - nema ograničenja broja pokušaja ni zaključavanja računa → neograničen brute force rječnikom.
/// </summary>
[ApiController]
[Route("api/lab11")]
public sealed class Lab11Controller(Db db) : ControllerBase
{
    private static readonly PasswordHasher<string> Hasher = new();

    public sealed record LoginRequest(string? Username, string? Password);

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var password = request.Password ?? string.Empty;

        var storedHash = db.Scalar(
            "SELECT password_hash FROM lab11_users WHERE username = $u", ("$u", username)) as string;

        // RANJIVO: poseban odgovor otkriva da korisnik ne postoji (enumeracija).
        if (storedHash is null)
        {
            return NotFound(new { error = "Korisnik ne postoji." });
        }

        // RANJIVO: nema brojanja neuspjelih pokušaja ni zaključavanja.
        if (Hasher.VerifyHashedPassword(username, storedHash, password) == PasswordVerificationResult.Failed)
        {
            return Unauthorized(new { error = "Pogrešna lozinka." });
        }

        return Ok(new { status = "prijavljen", username });
    }
}
