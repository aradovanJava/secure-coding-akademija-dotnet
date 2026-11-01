using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab03;

/// <summary>
/// "Interni" administratorski endpoint koji vraća tajne SAMO ako zahtjev dolazi s
/// loopback adrese (127.0.0.1 / ::1). Simulira interni servis dostupan samo s lokalnog
/// hosta ili interne mreže (npr. cloud metadata servis). Meta je SSRF vježbe (Lab03):
/// napadač preko <c>/api/lab03/preview</c> natjera poslužitelj da sam sebi pošalje zahtjev.
///
/// Endpoint namjerno nije zaštićen Bearer tokenom. Ovaj kontroler NIJE predmet popravka.
/// </summary>
[ApiController]
public sealed class InternalController : ControllerBase
{
    [HttpGet("/internal/admin/secrets")]
    public IActionResult Secrets()
    {
        var remote = HttpContext.Connection.RemoteIpAddress;
        if (remote is null || !IPAddress.IsLoopback(remote))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "Dostupno samo s loopback adrese." });
        }

        return Ok(new
        {
            dbPassword = "Sup3rTajn0!",
            paymentApiKey = "sk_live_akademija_123",
        });
    }
}
