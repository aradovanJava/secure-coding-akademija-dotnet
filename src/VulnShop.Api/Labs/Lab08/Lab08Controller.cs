using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab08;

/// <summary>
/// Lab08 – A05 Injection: Cross-Site Scripting (CWE-79).
///
/// ISPRAVLJENO:
///  - svaki korisnički podatak koji se upisuje u HTML kodira se za HTML kontekst
///    (<see cref="HtmlEncoder"/>: &lt; → &amp;lt;, &gt; → &amp;gt;, " → &amp;quot; …),
///  - validacija ulaza (obavezna polja, najveća duljina),
///  - zaglavlje <c>Content-Security-Policy</c> kao druga linija obrane (zabranjuje inline skripte).
/// Napomena: Razor (<c>@izraz</c>) kodira automatski; <c>Html.Raw</c> zaobilazi kodiranje i opasan je.
/// </summary>
[ApiController]
public sealed class Lab08Controller(Db db) : ControllerBase
{
    private const string ContentSecurityPolicy = "default-src 'self'; script-src 'self'; object-src 'none'";

    public sealed record ReviewRequest(long ProductId, string? Author, string? Text);

    [HttpGet("/lab08/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        q ??= string.Empty;
        if (q.Length > 100)
        {
            return BadRequest(new { error = "Upit može imati najviše 100 znakova." });
        }

        // ISPRAVLJENO: HTML kodiranje korisničkog unosa.
        var html = "<!DOCTYPE html><html lang=\"hr\"><head><meta charset=\"UTF-8\">" +
                   "<title>Pretraga</title></head><body>" +
                   "<h1>Rezultati pretrage za: " + HtmlEncoder.Default.Encode(q) + "</h1>" +
                   "<p>Nema pronađenih proizvoda.</p>" +
                   "</body></html>";
        return HtmlWithCsp(html);
    }

    [HttpPost("/api/lab08/reviews")]
    public IActionResult AddReview([FromBody] ReviewRequest request)
    {
        // ISPRAVLJENO: validacija ulaza.
        if (string.IsNullOrWhiteSpace(request.Author) || request.Author.Length > 50 ||
            string.IsNullOrWhiteSpace(request.Text) || request.Text.Length > 1000)
        {
            return BadRequest(new { error = "Autor (do 50 znakova) i tekst (do 1000 znakova) su obavezni." });
        }

        db.Execute(
            "INSERT INTO lab08_reviews (product_id, author, text) VALUES ($p, $a, $t)",
            ("$p", request.ProductId), ("$a", request.Author), ("$t", request.Text));
        return Ok(new { status = "spremljeno" });
    }

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
            // ISPRAVLJENO: kodiranje pri ISPISU (podaci u bazi mogu biti zlonamjerni).
            html.Append("<li><strong>").Append(HtmlEncoder.Default.Encode(row.GetString("author"))).Append("</strong>: ")
                .Append(HtmlEncoder.Default.Encode(row.GetString("text"))).Append("</li>");
        }
        html.Append("</ul></body></html>");
        return HtmlWithCsp(html.ToString());
    }

    private ContentResult HtmlWithCsp(string html)
    {
        Response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
        return Content(html, "text/html; charset=utf-8");
    }
}
