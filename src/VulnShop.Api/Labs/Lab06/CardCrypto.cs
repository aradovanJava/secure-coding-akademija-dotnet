using System.Security.Cryptography;
using System.Text;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio B) – šifriranje brojeva kartica.
///
/// ISPRAVLJENO:
///  - AES-GCM (autentificirano šifriranje) s nasumičnim 12-bajtnim nonceom za SVAKI zapis,
///  - pohranjuje se nonce || šifrat || oznaka (tag, 16 B), kodirano Base64,
///  - 256-bitni ključ dolazi iz konfiguracije (<c>Lab06:EncryptionKey</c>) – u produkciji iz
///    varijable okoline <c>Lab06__EncryptionKey</c> ili iz KMS-a / Azure Key Vaulta, nikad iz koda.
/// </summary>
public sealed class CardCrypto
{
    private const int NonceSize = 12; // AesGcm.NonceByteSizes.MaxSize
    private const int TagSize = 16;   // AesGcm.TagByteSizes.MaxSize

    private readonly byte[] _key;

    public CardCrypto(IConfiguration configuration)
    {
        var base64Key = configuration["Lab06:EncryptionKey"]
            ?? throw new InvalidOperationException("Nedostaje konfiguracijski ključ Lab06:EncryptionKey.");
        _key = Convert.FromBase64String(base64Key);
        if (_key.Length != 32)
        {
            throw new InvalidOperationException("Lab06:EncryptionKey mora imati 32 bajta (256 bita).");
        }
    }

    /// <summary>Šifrira broj kartice; rezultat je Base64(nonce || šifrat || tag).</summary>
    public string Encrypt(string cardNumber)
    {
        var plaintext = Encoding.UTF8.GetBytes(cardNumber);
        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        var ciphertext = output.AsSpan(NonceSize, plaintext.Length);
        var tag = output.AsSpan(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return Convert.ToBase64String(output);
    }

    /// <summary>Dešifrira i provjerava integritet (izmijenjen šifrat → CryptographicException).</summary>
    public string Decrypt(string base64Ciphertext)
    {
        var input = Convert.FromBase64String(base64Ciphertext);
        var nonce = input.AsSpan(0, NonceSize);
        var ciphertext = input.AsSpan(NonceSize, input.Length - NonceSize - TagSize);
        var tag = input.AsSpan(input.Length - TagSize, TagSize);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
