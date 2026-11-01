using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab14;

/// <summary>
/// Lab14 – A09 Security Logging and Alerting Failures (CWE-778, CWE-117, CWE-532).
///
/// ISPRAVLJENO:
///  - lozinka (i druge tajne) se NIKAD ne zapisuju u log,
///  - korisnički unos se prije logiranja neutralizira (CR/LF i ostali kontrolni znakovi → '_'),
///  - strukturirano logiranje s predloškom poruke (<c>{User}</c>), ne konkatenacijom,
///  - sigurnosni događaji: <c>SECURITY_EVENT LOGIN_FAILED</c> (Warning), <c>SECURITY_EVENT LOGIN_SUCCESS</c>
///    (Information) te <c>SECURITY_ALERT BRUTE_FORCE_SUSPECTED</c> (Error) nakon 5 neuspjeha za istog
///    korisnika unutar 5 minuta.
/// U produkciji: JSON logovi, centralizacija (SIEM), korelacijski ID, alarmi na SECURITY_ALERT.
/// </summary>
[ApiController]
[Route("api/lab14")]
public sealed class Lab14Controller(UserService users, IMemoryCache cache, ILogger<Lab14Controller> logger) : ControllerBase
{
    private const int AlertThreshold = 5;
    private static readonly TimeSpan AlertWindow = TimeSpan.FromMinutes(5);
    private static readonly object Sync = new();

    public sealed record LoginRequest(string? Username, string? Password);

    private sealed class FailureWindow
    {
        public int Count { get; set; }
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var safeUser = Sanitize(username);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "nepoznata";

        // ISPRAVLJENO: bez lozinke, s neutraliziranim korisničkim imenom.
        logger.LogInformation("Login attempt user={User}", safeUser);

        var user = users.VerifyCredentials(username, request.Password);
        if (user is null)
        {
            // ISPRAVLJENO: neuspjeh je sigurnosni događaj.
            logger.LogWarning("SECURITY_EVENT LOGIN_FAILED user={User} ip={Ip}", safeUser, ip);

            var failures = RegisterFailure(username);
            if (failures >= AlertThreshold)
            {
                logger.LogError(
                    "SECURITY_ALERT BRUTE_FORCE_SUSPECTED user={User} ip={Ip} failures={Failures} window={WindowMinutes}min",
                    safeUser, ip, failures, AlertWindow.TotalMinutes);
            }
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        logger.LogInformation("SECURITY_EVENT LOGIN_SUCCESS user={User} ip={Ip}", safeUser, ip);
        return Ok(new { status = "prijavljen", username = user.Username });
    }

    /// <summary>Neutralizira CR, LF i ostale kontrolne znakove (CWE-117) i skraćuje predug unos.</summary>
    public static string Sanitize(string value)
    {
        var chars = value.Select(c => char.IsControl(c) ? '_' : c).ToArray();
        var cleaned = new string(chars);
        return cleaned.Length > 100 ? cleaned[..100] + "…" : cleaned;
    }

    private int RegisterFailure(string username)
    {
        lock (Sync)
        {
            // Prozor od 5 minuta počinje prvim neuspjehom (apsolutni istek zapisa u cacheu).
            var window = cache.GetOrCreate("lab14:failures:" + username.ToLowerInvariant(), entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = AlertWindow;
                return new FailureWindow();
            })!;
            window.Count++;
            return window.Count;
        }
    }
}
