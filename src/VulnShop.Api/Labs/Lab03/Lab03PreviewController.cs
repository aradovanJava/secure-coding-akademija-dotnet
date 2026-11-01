using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab03;

/// <summary>
/// Lab03 – A01 Broken Access Control: Server-Side Request Forgery (CWE-918).
///
/// RANJIVO: endpoint "pregled poveznice" dohvaća proizvoljan URL koji je zadao korisnik i
/// vraća prvih 2000 znakova sadržaja. Nema provjere sheme ni odredišta, slijede se
/// preusmjeravanja, pa napadač može dosegnuti interne servise (loopback,
/// <c>/internal/admin/secrets</c>, cloud metadata na 169.254.169.254, interna mreža).
/// </summary>
[ApiController]
[Route("api/lab03")]
[RequireAuth]
public sealed class Lab03PreviewController : ControllerBase
{
    private const int MaxChars = 2000;

    // RANJIVO: preusmjeravanja su uključena (AllowAutoRedirect = true).
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = true,
        ConnectTimeout = TimeSpan.FromSeconds(3),
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
    };

    [HttpGet("preview")]
    public async Task<IActionResult> Preview([FromQuery] string url)
    {
        Uri target;
        try
        {
            target = new Uri(url, UriKind.Absolute);
        }
        catch (UriFormatException)
        {
            return BadRequest(new { error = "Neispravan URL." });
        }

        try
        {
            // RANJIVO: nikakva provjera sheme ni odredišta (host/IP) prije dohvata.
            using var response = await Client.GetAsync(target);
            var body = await response.Content.ReadAsStringAsync();
            var content = body.Length > MaxChars ? body[..MaxChars] : body;
            return Ok(new { url, status = (int)response.StatusCode, content });
        }
        catch (Exception ex)
        {
            // Nepodržana shema (npr. ftp://) ili neuspješan dohvat → 502.
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "Dohvat nije uspio: " + ex.Message });
        }
    }
}
