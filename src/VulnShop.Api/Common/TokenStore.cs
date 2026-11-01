using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace VulnShop.Api.Common;

/// <summary>
/// Pohrana nasumičnih (opaque) pristupnih tokena za zajedničku autentikaciju.
/// Token = 32 nasumična bajta (CSPRNG) kodirana kao Base64URL. Implementirano ISPRAVNO
/// (nije dio vježbi).
/// </summary>
public sealed class TokenStore
{
    private readonly ConcurrentDictionary<string, AuthUser> _tokens = new(StringComparer.Ordinal);

    public string Issue(AuthUser user)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _tokens[token] = user;
        return token;
    }

    public bool TryGet(string token, out AuthUser? user) => _tokens.TryGetValue(token, out user);
}
