using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace VulnShop.Api.Labs.Lab05;

/// <summary>
/// Lab05 – A03 Software Supply Chain Failures (CWE-1104, CWE-1395).
///
/// RANJIVO: projekt koristi zastarjeli paket <c>Newtonsoft.Json 12.0.3</c> s poznatom
/// ranjivošću GHSA-5crp-9r3c-p9vr: bez ograničenja dubine (<c>MaxDepth</c>) duboko
/// ugniježđen JSON (npr. 100 000 znakova <c>[</c>) izaziva <c>StackOverflowException</c>
/// koji ruši CIJELI proces (DoS) – takva se iznimka u .NET-u ne može uhvatiti.
/// Ispravljeno u 13.0.1 (zadani <c>MaxDepth = 64</c>).
///
/// Dodatno: tijelo zahtjeva se čita bez ograničenja veličine i bez hvatanja grešaka parsiranja.
/// </summary>
[ApiController]
[Route("api/lab05")]
public sealed class Lab05ImportController : ControllerBase
{
    [HttpPost("import")]
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var body = await reader.ReadToEndAsync();

        // RANJIVO: zadane postavke ranjive verzije biblioteke (bez MaxDepth), bez try/catch.
        var token = JsonConvert.DeserializeObject<JToken>(body);

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
