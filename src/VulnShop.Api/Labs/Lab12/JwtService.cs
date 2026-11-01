using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VulnShop.Api.Labs.Lab12;

/// <summary>
/// Lab12 – RUČNA implementacija JWT-a (HS256) BEZ vanjskih biblioteka: Base64URL + HMAC-SHA256.
///
/// ISPRAVLJENO:
///  - 256-bitna nasumična tajna iz konfiguracije (<c>Lab12:JwtSecret</c>, Base64) – u produkciji iz
///    varijable okoline <c>Lab12__JwtSecret</c> ili Key Vaulta; nikad u kodu,
///  - allowlista algoritma: prihvaća se ISKLJUČIVO <c>HS256</c> (<c>none</c> i sve ostalo → odbijeno),
///  - potpis se uspoređuje u konstantnom vremenu (<see cref="CryptographicOperations.FixedTimeEquals"/>),
///  - obavezni su <c>exp</c> (mora biti u budućnosti) i <c>iss</c> (mora odgovarati očekivanom izdavatelju).
/// U stvarnim projektima koristite provjerenu biblioteku (Microsoft.IdentityModel.JsonWebTokens,
/// <c>AddJwtBearer</c>) umjesto vlastite implementacije.
/// </summary>
public sealed class JwtService
{
    private readonly byte[] _secret;
    private readonly string _issuer;

    public JwtService(IConfiguration configuration)
    {
        var base64Secret = configuration["Lab12:JwtSecret"]
            ?? throw new InvalidOperationException("Nedostaje konfiguracijski ključ Lab12:JwtSecret.");
        _secret = Convert.FromBase64String(base64Secret);
        if (_secret.Length < 32)
        {
            throw new InvalidOperationException("Lab12:JwtSecret mora imati barem 256 bita (32 bajta).");
        }
        _issuer = configuration["Lab12:Issuer"] ?? "vulnshop-akademija";
    }

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
            ["iss"] = _issuer,
            ["sub"] = username,
            ["role"] = role,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        var signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
                           Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return signingInput + "." + Base64Url.Encode(Sign(signingInput));
    }

    /// <summary>ISPRAVLJENA provjera tokena. Vraća <c>null</c> ako token nije prihvaćen.</summary>
    public VerifiedToken? Verify(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || parts[2].Length == 0)
            {
                return null;
            }

            // ISPRAVLJENO: algoritam NE bira klijent – prihvaćamo samo HS256.
            var header = JsonNode.Parse(Base64Url.Decode(parts[0]))!.AsObject();
            if (header["alg"]?.GetValue<string>() != "HS256")
            {
                return null;
            }

            // ISPRAVLJENO: usporedba potpisa u konstantnom vremenu.
            var expected = Sign(parts[0] + "." + parts[1]);
            if (!CryptographicOperations.FixedTimeEquals(expected, Base64Url.Decode(parts[2])))
            {
                return null;
            }

            // ISPRAVLJENO: exp je obavezan i mora biti u budućnosti; iss mora odgovarati.
            var payload = JsonNode.Parse(Base64Url.Decode(parts[1]))!.AsObject();
            var exp = payload["exp"]?.GetValue<long>();
            if (exp is null || DateTimeOffset.FromUnixTimeSeconds(exp.Value) <= DateTimeOffset.UtcNow)
            {
                return null;
            }
            if (payload["iss"]?.GetValue<string>() != _issuer)
            {
                return null;
            }

            return new VerifiedToken(
                payload["sub"]?.GetValue<string>() ?? string.Empty,
                payload["role"]?.GetValue<string>() ?? string.Empty,
                exp);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private byte[] Sign(string signingInput) =>
        HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(signingInput));
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
