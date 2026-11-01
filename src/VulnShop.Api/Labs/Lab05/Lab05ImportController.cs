using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace VulnShop.Api.Labs.Lab05;

/// <summary>
/// Lab05 – A03 Software Supply Chain Failures (CWE-1104, CWE-1395).
///
/// ISPRAVLJENO:
///  - paket nadograđen na <c>Newtonsoft.Json 13.0.3</c> (VulnShop.Api.csproj),
///  - eksplicitno ograničenje dubine (<c>MaxDepth = 32</c>) – ne oslanjamo se na zadane vrijednosti,
///  - ograničena veličina tijela zahtjeva (<c>[RequestSizeLimit]</c>),
///  - greška parsiranja (<c>JsonReaderException</c>) → 400 Bad Request.
/// </summary>
[ApiController]
[Route("api/lab05")]
public sealed class Lab05ImportController : ControllerBase
{
    private const int MaxDepth = 32;

    [HttpPost("import")]
    [RequestSizeLimit(64 * 1024)] // 64 KB
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var body = await reader.ReadToEndAsync();

        JToken? token;
        try
        {
            token = JsonConvert.DeserializeObject<JToken>(body, new JsonSerializerSettings { MaxDepth = MaxDepth });
        }
        catch (JsonReaderException)
        {
            return BadRequest(new { error = $"Neispravan JSON ili preduboka struktura (najviše {MaxDepth} razina)." });
        }

        var (elements, depth) = JsonStats.Measure(token);
        return Ok(new { type = token?.Type.ToString(), elements, depth });
    }
}

/// <summary>Iterativno (bez rekurzije) broji elemente JSON stabla i mjeri njegovu dubinu.</summary>
public static class JsonStats
{
    public static (int Elements, int Depth) Measure(JToken? root)
    {
        if (root is null)
        {
            return (0, 0);
        }

        var elements = 0;
        var maxDepth = 0;
        var stack = new Stack<(JToken Token, int Depth)>();
        stack.Push((root, 1));
        while (stack.Count > 0)
        {
            var (token, depth) = stack.Pop();
            elements++;
            maxDepth = Math.Max(maxDepth, depth);
            foreach (var child in token.Children())
            {
                // JProperty je samo "omotač" para ime–vrijednost; brojimo njegovu vrijednost.
                var value = child is JProperty property ? property.Value : child;
                stack.Push((value, depth + 1));
            }
        }
        return (elements, maxDepth);
    }
}
