using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace VulnShop.Api.Labs.Lab13;

/// <summary>
/// Lab13 – A08 Software or Data Integrity Failures: nesigurna deserijalizacija (CWE-502).
///
/// RANJIVO: tijelo zahtjeva deserijalizira se Newtonsoft.Json-om uz
/// <c>TypeNameHandling.All</c>. Svojstvo <c>$type</c> u JSON-u tada određuje KOJA će se .NET
/// klasa instancirati – napadač može zatražiti bilo koju dostupnu klasu (gadget), npr.
/// <see cref="DiagnosticsTask"/>, čiji se kod izvrši već tijekom deserijalizacije.
/// </summary>
[ApiController]
[Route("api/lab13")]
public sealed class Lab13Controller : ControllerBase
{
    [HttpPost("cart/import")]
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var body = await reader.ReadToEndAsync();

        try
        {
            // RANJIVO: tip objekta bira klijent ($type).
            var obj = JsonConvert.DeserializeObject(body, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All,
            });

            // Klijent bez "$type" dobiva JObject koji pretvaramo u košaricu.
            var cart = obj switch
            {
                Cart c => c,
                JObject json => json.ToObject<Cart>(),
                _ => null,
            };
            if (cart is not null)
            {
                return Ok(new { status = "ok", itemCount = cart.Items.Count });
            }

            // Stigao je objekt neke druge klase – ali njegov kod se VEĆ izvršio tijekom deserijalizacije.
            return Ok(new { status = "ok", type = obj?.GetType().Name });
        }
        catch (JsonException)
        {
            return BadRequest(new { error = "Neispravan sadržaj košarice." });
        }
    }
}
