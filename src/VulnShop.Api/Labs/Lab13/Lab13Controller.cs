using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab13;

/// <summary>
/// Lab13 – A08 Software or Data Integrity Failures: nesigurna deserijalizacija (CWE-502).
///
/// ISPRAVLJENO:
///  - tip objekta određuje POSLUŽITELJ, ne klijent: deserijalizira se isključivo u konkretan DTO
///    (<see cref="CartImportRequest"/>) pomoću System.Text.Json, koji ne podržava "$type" za
///    proizvoljne klase,
///  - nepoznata svojstva (npr. "$type", "ReportPath") su greška (<c>JsonUnmappedMemberHandling.Disallow</c>),
///  - validacija sadržaja (1–50 stavki, količina 1–10) → inače 400.
/// Ako polimorfizam baš treba (Newtonsoft): <c>TypeNameHandling.None</c> ili <c>ISerializationBinder</c>
/// s allowlistom dopuštenih tipova.
/// </summary>
[ApiController]
[Route("api/lab13")]
public sealed class Lab13Controller : ControllerBase
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8,
    };

    /// <summary>DTO za uvoz košarice – samo podaci, bez ponašanja.</summary>
    public sealed record CartImportRequest(string? Owner, List<CartItemDto>? Items);

    public sealed record CartItemDto(long ProductId, string? Name, int Quantity);

    [HttpPost("cart/import")]
    [RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> Import()
    {
        CartImportRequest? request;
        try
        {
            // ISPRAVLJENO: fiksni ciljni tip (DTO), bez TypeNameHandling.
            request = await JsonSerializer.DeserializeAsync<CartImportRequest>(Request.Body, Options);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return BadRequest(new { error = "Neispravan sadržaj košarice." });
        }

        if (request?.Items is not { Count: >= 1 and <= 50 } items || items.Any(i => i.Quantity is < 1 or > 10))
        {
            return BadRequest(new { error = "Košarica mora imati 1–50 stavki s količinom 1–10." });
        }

        var cart = new Cart
        {
            Owner = request.Owner,
            Items = items.Select(i => new CartItem { ProductId = i.ProductId, Name = i.Name, Quantity = i.Quantity }).ToList(),
        };
        return Ok(new { status = "ok", itemCount = cart.Items.Count });
    }
}
