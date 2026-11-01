using System.Globalization;
using System.Security.Cryptography;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio A) – pohrana lozinki kupaca.
///
/// ISPRAVLJENO: PBKDF2-HMAC-SHA256 (<see cref="Rfc2898DeriveBytes.Pbkdf2(string, byte[], int, HashAlgorithmName, int)"/>)
/// s 600 000 iteracija (preporuka OWASP-a) i nasumičnom solju od 16 B za SVAKU lozinku.
/// Zapis: <c>pbkdf2-sha256$&lt;iteracije&gt;$&lt;sol Base64&gt;$&lt;hash Base64&gt;</c> – parametri su
/// pohranjeni uz hash pa se broj iteracija kasnije može povećati.
/// Alternativa: <c>PasswordHasher&lt;T&gt;</c> iz ASP.NET Core Identityja.
/// </summary>
public static class Lab06Passwords
{
    private const string Prefix = "pbkdf2-sha256";
    private const int Iterations = 600_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string storedHash)
    {
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations))
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        // Usporedba u konstantnom vremenu.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
