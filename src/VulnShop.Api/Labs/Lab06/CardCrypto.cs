using System.Security.Cryptography;
using System.Text;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio B) – šifriranje brojeva kartica.
///
/// RANJIVO (CWE-327, CWE-321, CWE-329):
///  - AES u načinu ECB: isti otvoreni tekst uvijek daje isti šifrat (vide se uzorci, nema IV-a),
///  - nema autentikacije (integriteta) šifrata,
///  - ključ je HARDKODIRAN u izvornom kodu ("AkademijaKljuc16") – tko ima kod (repozitorij,
///    dekompajlirani DLL), ima i ključ.
/// </summary>
public sealed class CardCrypto
{
    // RANJIVO: hardkodirani 16-bajtni ključ izravno u izvornom kodu.
    private static readonly byte[] HardcodedKey = Encoding.UTF8.GetBytes("AkademijaKljuc16");

    /// <summary>Šifrira broj kartice i vraća Base64 zapis šifrata.</summary>
    public string Encrypt(string cardNumber)
    {
        using var aes = Aes.Create();
        aes.Key = HardcodedKey;
        // RANJIVO: ECB način rada, bez IV-a i bez autentikacijske oznake (taga).
        var ciphertext = aes.EncryptEcb(Encoding.UTF8.GetBytes(cardNumber), PaddingMode.PKCS7);
        return Convert.ToBase64String(ciphertext);
    }

    /// <summary>Dešifrira Base64 šifrat natrag u broj kartice.</summary>
    public string Decrypt(string base64Ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = HardcodedKey;
        var plaintext = aes.DecryptEcb(Convert.FromBase64String(base64Ciphertext), PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plaintext);
    }
}
