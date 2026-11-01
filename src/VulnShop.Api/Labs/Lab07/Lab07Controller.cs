using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab07;

/// <summary>
/// Lab07 – A05 Injection: SQL injection (CWE-89).
///
/// ISPRAVLJENO: svi upiti su PARAMETRIZIRANI (<c>SqliteCommand.Parameters</c>) – korisnički unos
/// nikad ne postaje dio SQL naredbe, nego se šalje odvojeno kao podatak. Dodatno: escape
/// zamjenskih znakova za LIKE (<c>%</c>, <c>_</c>) i ograničenje duljine ulaza.
/// </summary>
[ApiController]
[Route("api/lab07")]
public sealed class Lab07Controller(Db db) : ControllerBase
{
    private const int MaxQueryLength = 100;

    public sealed record LoginRequest(string? Username, string? Password);

    [HttpGet("products/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        q ??= string.Empty;
        if (q.Length > MaxQueryLength)
        {
            return BadRequest(new { error = $"Upit može imati najviše {MaxQueryLength} znakova." });
        }

        // ISPRAVLJENO: parametar $pattern + escape znakova \, % i _ (LIKE ... ESCAPE '\').
        var pattern = "%" + q.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var rows = db.Query(
            "SELECT id, name, description, price FROM lab07_products " +
            "WHERE hidden = 0 AND name LIKE $pattern ESCAPE '\\'",
            ("$pattern", pattern));

        return Ok(rows.Select(r => new
        {
            id = r["id"],
            name = r["name"],
            description = r["description"],
            price = r["price"],
        }));
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password) ||
            request.Username.Length > 100 || request.Password.Length > 100)
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        // ISPRAVLJENO: parametrizirani upit.
        // (Lozinke u čistom tekstu i dalje su loša praksa – vidi Lab06; ovdje su zadržane radi vježbe.)
        var rows = db.Query(
            "SELECT id, username FROM lab07_accounts WHERE username = $u AND password = $p",
            ("$u", request.Username), ("$p", request.Password));
        if (rows.Count == 0)
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }
        return Ok(new { status = "prijavljen", username = rows[0].GetString("username") });
    }
}
