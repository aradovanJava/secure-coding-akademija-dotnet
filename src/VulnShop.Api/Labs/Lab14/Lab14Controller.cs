using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab14;

/// <summary>
/// Lab14 – A09 Security Logging and Alerting Failures (CWE-778, CWE-117, CWE-532).
///
/// RANJIVO:
///  - lozinka se zapisuje u log (CWE-532),
///  - korisničko ime se zapisuje bez neutralizacije znakova CR/LF, pa napadač može
///    krivotvoriti cijele retke loga (log injection, CWE-117),
///  - neuspjela prijava se uopće ne bilježi – nema sigurnosnog događaja ni upozorenja
///    na brute force (CWE-778).
/// </summary>
[ApiController]
[Route("api/lab14")]
public sealed class Lab14Controller(UserService users, ILogger<Lab14Controller> logger) : ControllerBase
{
    public sealed record LoginRequest(string? Username, string? Password);

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var password = request.Password ?? string.Empty;

        // RANJIVO: lozinka u logu + korisničko ime bez neutralizacije CR/LF.
        logger.LogInformation("Login attempt user=" + username + " password=" + password);

        var user = users.VerifyCredentials(username, password);
        if (user is null)
        {
            // RANJIVO: neuspjeh se ne bilježi.
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        return Ok(new { status = "prijavljen", username = user.Username });
    }
}
