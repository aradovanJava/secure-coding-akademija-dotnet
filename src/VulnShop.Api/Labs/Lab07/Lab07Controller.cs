using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab07;

/// <summary>
/// Lab07 – A05 Injection: SQL injection (CWE-89).
///
/// RANJIVO: i pretraga proizvoda i prijava grade SQL upit KONKATENACIJOM korisničkog
/// unosa. Napadač može dohvatiti skrivene proizvode (<c>%' OR '1'='1</c>), izvući podatke
/// iz drugih tablica (UNION SELECT) ili zaobići prijavu (<c>admin'--</c>).
/// </summary>
[ApiController]
[Route("api/lab07")]
public sealed class Lab07Controller(Db db) : ControllerBase
{
    public sealed record LoginRequest(string? Username, string? Password);

    [HttpGet("products/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        // RANJIVO: q se umeće izravno u SQL naredbu.
        var sql = "SELECT id, name, description, price FROM lab07_products " +
                  "WHERE hidden = 0 AND name LIKE '%" + q + "%'";
        try
        {
            var rows = db.Use(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = sql;
                return Db.ReadAll(cmd);
            });
            return Ok(rows.Select(r => new
            {
                id = r["id"],
                name = r["name"],
                description = r["description"],
                price = r["price"],
            }));
        }
        catch (Exception)
        {
            return BadRequest(new { error = "Greška u upitu." });
        }
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var u = request.Username ?? string.Empty;
        var p = request.Password ?? string.Empty;

        // RANJIVO: korisničko ime i lozinka umeću se izravno u SQL naredbu.
        var sql = "SELECT id, username FROM lab07_accounts WHERE username = '" + u +
                  "' AND password = '" + p + "'";
        try
        {
            var rows = db.Use(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = sql;
                return Db.ReadAll(cmd);
            });
            if (rows.Count == 0)
            {
                return Unauthorized(new { error = "Neispravni podaci." });
            }
            return Ok(new { status = "prijavljen", username = rows[0].GetString("username") });
        }
        catch (Exception)
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }
    }
}
