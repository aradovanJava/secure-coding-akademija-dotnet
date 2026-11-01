using System.Text;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab08;

/// <summary>
/// Lab08 – A05 Injection: Cross-Site Scripting (CWE-79).
///
/// RANJIVO:
///  - reflektirani XSS: <c>GET /lab08/search?q=...</c> upisuje q izravno u HTML,
///  - pohranjeni XSS: recenzije (<c>author</c>, <c>text</c>) se spremaju bez validacije i
///    ispisuju u HTML konkatenacijom stringova na <c>GET /lab08/products/{id}/reviews</c>,
///  - nema zaglavlja Content-Security-Policy koje bi ograničilo izvršavanje skripti.
/// </summary>
[ApiController]
public sealed class Lab08Controller(Db db) : ControllerBase
{
    public sealed record ReviewRequest(long ProductId, string? Author, string? Text);

    /// <summary>RANJIVO: reflektirani XSS – q se upisuje izravno u HTML.</summary>
    [HttpGet("/lab08/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        var html = "<!DOCTYPE html><html lang=\"hr\"><head><meta charset=\"UTF-8\">" +
                   "<title>Pretraga</title></head><body>" +
                   "<h1>Rezultati pretrage za: " + q + "</h1>" +
                   "<p>Nema pronađenih proizvoda.</p>" +
                   "</body></html>";
        return Content(html, "text/html; charset=utf-8");
    }

    [HttpPost("/api/lab08/reviews")]
    public IActionResult AddReview([FromBody] ReviewRequest request)
    {
        // RANJIVO: nema validacije ulaza (duljina, obavezna polja).
        db.Execute(
            "INSERT INTO lab08_reviews (product_id, author, text) VALUES ($p, $a, $t)",
            ("$p", request.ProductId), ("$a", request.Author ?? string.Empty), ("$t", request.Text ?? string.Empty));
        return Ok(new { status = "spremljeno" });
    }

    /// <summary>RANJIVO: pohranjeni XSS – author i text se upisuju izravno u HTML.</summary>
    [HttpGet("/lab08/products/{id:long}/reviews")]
    public IActionResult Reviews(long id)
    {
        var rows = db.Query(
            "SELECT author, text FROM lab08_reviews WHERE product_id = $p ORDER BY id", ("$p", id));

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html lang=\"hr\"><head><meta charset=\"UTF-8\">")
            .Append("<title>Recenzije</title></head><body>")
            .Append("<h1>Recenzije za proizvod ").Append(id).Append("</h1><ul>");
        foreach (var row in rows)
        {
            html.Append("<li><strong>").Append(row.GetString("author")).Append("</strong>: ")
                .Append(row.GetString("text")).Append("</li>");
        }
        html.Append("</ul></body></html>");
        return Content(html.ToString(), "text/html; charset=utf-8");
    }
}
