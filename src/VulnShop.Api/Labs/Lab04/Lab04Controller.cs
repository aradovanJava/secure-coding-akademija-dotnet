using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration.
///
/// ISPRAVLJENO: <c>GET /api/lab04/debug/config</c> postoji samo u okruženju Development
/// (inače 404), a i tada su vrijednosti osjetljivih ključeva (Key, Secret, Password …) maskirane.
/// </summary>
[ApiController]
[Route("api/lab04")]
public sealed class Lab04Controller(IConfiguration configuration, IWebHostEnvironment environment) : ControllerBase
{
    private static readonly string[] SensitiveMarkers = ["key", "secret", "password", "token", "connectionstring"];

    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { status = "ok" });

    [HttpGet("crash")]
    public IActionResult Crash() =>
        throw new InvalidOperationException(
            "Neuspjelo spajanje na bazu 'vulnshop-prod' (korisnik: sa, host: db.interno.local:1433)");

    /// <summary>ISPRAVLJENO: samo u Developmentu i s maskiranim tajnama.</summary>
    [HttpGet("debug/config")]
    public IActionResult DebugConfig()
    {
        if (!environment.IsDevelopment())
        {
            return NotFound();
        }

        return Ok(configuration.AsEnumerable()
            .Where(kv => kv.Value is not null)
            .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(kv => kv.Key, kv => IsSensitive(kv.Key) ? "***" : kv.Value));
    }

    private static bool IsSensitive(string key) =>
        SensitiveMarkers.Any(marker => key.Contains(marker, StringComparison.OrdinalIgnoreCase));
}
