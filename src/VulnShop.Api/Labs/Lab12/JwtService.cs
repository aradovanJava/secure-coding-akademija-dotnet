using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VulnShop.Api.Labs.Lab12;

/// <summary>
/// Lab12 – RUČNA implementacija JWT-a (HS256) BEZ vanjskih biblioteka: Base64URL + HMAC-SHA256.
///
/// RANJIVO (CWE-347, CWE-798, CWE-613):
///  - tajna za potpis je slaba i HARDKODIRANA (<c>secret123</c>) – nalazi se u svakom rječniku,
///  - verifikator čita <c>alg</c> iz zaglavlja tokena i za <c>none</c> PRESKAČE provjeru potpisa,
///  - <c>exp</c> se ne provjerava (istekli token vrijedi zauvijek),
///  - potpis se uspoređuje običnom usporedbom stringova (nije u konstantnom vremenu).
/// </summary>
public sealed class JwtService
{
    // RANJIVO: slaba, hardkodirana tajna.
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("secret123");

    /// <summary>Rezultat uspješne provjere tokena.</summary>
    public sealed record VerifiedToken(string Subject, string Role, long? ExpiresAt);

    /// <summary>Izrađuje token koji vrijedi 15 minuta.</summary>
    public string CreateToken(string username, string role) =>
        CreateToken(username, role, DateTimeOffset.UtcNow.AddMinutes(15));

    /// <summary>
    /// Izrađuje HS256 token s proizvoljnim vremenom isteka (javna metoda – testovi pomoću nje
    /// izrađuju istekli token potpisan ISPRAVNIM ključem).
    /// </summary>
    public string CreateToken(string username, string role, DateTimeOffset expiresAt)
    {
        var header = new JsonObject { ["alg"] = "HS256", ["typ"] = "JWT" };
        var payload = new JsonObject
        {
            ["sub"] = username,
            ["role"] = role,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        var signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
                           Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return signingInput + "." + Base64Url.Encode(Sign(signingInput));
    }

    /// <summary>RANJIVA provjera tokena. Vraća <c>null</c> ako token nije prihvaćen.</summary>
    public VerifiedToken? Verify(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length < 2)
            {
                return null;
            }

            var header = JsonNode.Parse(Base64Url.Decode(parts[0]))!.AsObject();
            var payload = JsonNode.Parse(Base64Url.Decode(parts[1]))!.AsObject();
            var alg = header["alg"]?.GetValue<string>();

            // RANJIVO: algoritam bira NAPADAČ (zaglavlje tokena); "none" preskače provjeru potpisa.
            if (!string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                if (parts.Length != 3)
                {
                    return null;
                }
                var expected = Base64Url.Encode(Sign(parts[0] + "." + parts[1]));
                // RANJIVO: obična usporedba stringova (nije u konstantnom vremenu).
                if (expected != parts[2])
                {
                    return null;
                }
            }

            // RANJIVO: exp se ne provjerava.
            return new VerifiedToken(
                payload["sub"]?.GetValue<string>() ?? string.Empty,
                payload["role"]?.GetValue<string>() ?? string.Empty,
                payload["exp"]?.GetValue<long>());
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static byte[] Sign(string signingInput) =>
        HMACSHA256.HashData(Secret, Encoding.UTF8.GetBytes(signingInput));
}

/// <summary>Base64URL kodiranje (RFC 4648 §5) bez znakova za dopunu (=).</summary>
public static class Base64Url
{
    public static string Encode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        s = (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            _ => s,
        };
        return Convert.FromBase64String(s);
    }
}
