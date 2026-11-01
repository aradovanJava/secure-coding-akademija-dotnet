using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration.
///
/// RANJIVO: <c>GET /api/lab04/debug/config</c> vraća SVE ključeve konfiguracije (analogno
/// Spring Boot <c>/actuator/env</c>), uključujući tajne poput <c>Payment:ApiKey</c>,
/// i dostupan je u svakom okruženju, bez autentikacije.
/// </summary>
[ApiController]
[Route("api/lab04")]
public sealed class Lab04Controller(IConfiguration configuration) : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { status = "ok" });

    [HttpGet("crash")]
    public IActionResult Crash() =>
        // Simulira grešku s osjetljivim detaljima u poruci (naziv baze, korisnik, interni host).
        throw new InvalidOperationException(
            "Neuspjelo spajanje na bazu 'vulnshop-prod' (korisnik: sa, host: db.interno.local:1433)");

    /// <summary>RANJIVO: ispis cijele konfiguracije, uključujući tajne.</summary>
    [HttpGet("debug/config")]
    public IActionResult DebugConfig() =>
        Ok(configuration.AsEnumerable()
            .Where(kv => kv.Value is not null)
            .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(kv => kv.Key, kv => kv.Value));
}
