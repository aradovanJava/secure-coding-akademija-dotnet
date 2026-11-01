using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab11;

/// <summary>
/// Lab11 – A07 Authentication Failures: brute force i enumeracija korisnika (CWE-307, CWE-204).
///
/// ISPRAVLJENO:
///  - jedinstven odgovor 401 "Neispravno korisničko ime ili lozinka." za nepostojećeg korisnika
///    i za krivu lozinku,
///  - lozinka se provjerava i za nepostojećeg korisnika (lažni hash) – ujednačeno vrijeme odgovora,
///  - nakon 5 neuspjelih pokušaja korisničko ime se zaključava na 15 minuta → 429 Too Many Requests
///    (brojač se vodi za svako korisničko ime, i za nepostojeće, pa ni zaključavanje ne otkriva
///    postoji li račun).
/// U produkciji dodatno: MFA, CAPTCHA nakon nekoliko pokušaja, rate limiting po IP adresi
/// (<c>Microsoft.AspNetCore.RateLimiting</c>), obavijest korisniku o sumnjivim prijavama.
/// </summary>
[ApiController]
[Route("api/lab11")]
public sealed class Lab11Controller(Db db, IMemoryCache cache) : ControllerBase
{
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly PasswordHasher<string> Hasher = new();
    private static readonly string DummyHash = Hasher.HashPassword(string.Empty, "lazna-lozinka-za-ujednaceno-vrijeme");
    private static readonly object Sync = new();

    public sealed record LoginRequest(string? Username, string? Password);

    private sealed class AttemptState
    {
        public int Failures { get; set; }
        public DateTimeOffset? LockedUntil { get; set; }
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var password = request.Password ?? string.Empty;
        var state = GetState(username);

        // ISPRAVLJENO: zaključan račun → 429 (i prije provjere lozinke).
        lock (Sync)
        {
            if (state.LockedUntil is { } until && until > DateTimeOffset.UtcNow)
            {
                return StatusCode(StatusCodes.Status429TooManyRequests,
                    new { error = "Previše neuspjelih pokušaja. Pokušajte ponovno za 15 minuta." });
            }
        }

        var storedHash = db.Scalar(
            "SELECT password_hash FROM lab11_users WHERE username = $u", ("$u", username)) as string;

        // ISPRAVLJENO: hash se provjerava UVIJEK (lažni hash za nepostojećeg korisnika) – isto vrijeme.
        var passwordOk = Hasher.VerifyHashedPassword(username, storedHash ?? DummyHash, password)
                         != PasswordVerificationResult.Failed;

        if (storedHash is null || !passwordOk)
        {
            lock (Sync)
            {
                state.Failures++;
                if (state.Failures >= MaxFailedAttempts)
                {
                    state.LockedUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
                    state.Failures = 0;
                }
            }
            // ISPRAVLJENO: jedinstven odgovor – ne otkriva postoji li korisnik.
            return Unauthorized(new { error = "Neispravno korisničko ime ili lozinka." });
        }

        lock (Sync)
        {
            state.Failures = 0;
        }
        return Ok(new { status = "prijavljen", username });
    }

    private AttemptState GetState(string username) =>
        cache.GetOrCreate("lab11:attempts:" + username.ToLowerInvariant(), entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromHours(1);
            return new AttemptState();
        })!;
}
