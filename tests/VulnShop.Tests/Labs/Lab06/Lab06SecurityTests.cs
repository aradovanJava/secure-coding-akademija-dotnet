using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace VulnShop.Tests.Labs.Lab06;

/// <summary>
/// Lab06 – sigurnosni testovi (kriptografski propusti).
/// Dio A: pohrana lozinki. Dio B: šifriranje brojeva kartica.
/// Svaki test koristi vlastita, nasumična korisnička imena.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab06")]
public sealed class Lab06SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    private const string CardNumber = "4111111111111111";

    // Dio A: dva korisnika s ISTOM lozinkom moraju imati RAZLIČITE hasheve (nasumična sol).
    [Fact]
    public async Task SamePasswordProducesDifferentHashes()
    {
        var client = factory.CreateClient();
        var user1 = "kupac_" + Guid.NewGuid().ToString("N")[..8];
        var user2 = "kupac_" + Guid.NewGuid().ToString("N")[..8];
        await client.PostAsJsonAsync("/api/lab06/register", new { username = user1, password = "Ljeto2026!" });
        await client.PostAsJsonAsync("/api/lab06/register", new { username = user2, password = "Ljeto2026!" });

        var hashes = await GetExportedHashesAsync(client);

        Assert.NotEqual(hashes[user1], hashes[user2]);
    }

    // Dio A: pohranjeni hash nije MD5 lozinke niti ima oblik MD5 heksa (32 heksadecimalna znaka).
    [Fact]
    public async Task StoredHashIsNotUnsaltedMd5()
    {
        var client = factory.CreateClient();
        var user = "kupac_" + Guid.NewGuid().ToString("N")[..8];
        const string password = "Jesen2026!";
        await client.PostAsJsonAsync("/api/lab06/register", new { username = user, password });

        var hash = (await GetExportedHashesAsync(client))[user];

        var md5 = Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(password)));
        Assert.False(string.Equals(md5, hash, StringComparison.OrdinalIgnoreCase),
            "Pohranjeni hash je običan MD5 lozinke (bez soli).");
        Assert.DoesNotMatch(new Regex("^[0-9a-fA-F]{32}$"), hash);
    }

    // Dio A: i seed kupci (ivan i maja imaju istu lozinku) moraju biti hashirani novom metodom.
    [Fact]
    public async Task SeedCustomersWithSamePasswordHaveDifferentHashes()
    {
        var hashes = await GetExportedHashesAsync(factory.CreateClient());

        Assert.NotEqual(hashes["ivan"], hashes["maja"]);
    }

    // Dio B: isti broj kartice šifriran dvaput daje RAZLIČITE šifrate (nasumični IV/nonce, ne ECB).
    [Fact]
    public async Task SameCardNumberProducesDifferentCiphertexts()
    {
        var client = factory.CreateClient();

        var first = await StoreCardAsync(client, CardNumber);
        var second = await StoreCardAsync(client, CardNumber);

        Assert.NotEqual(first, second);
    }

    // Dio B: šifrat sadrži nonce (12 B) i autentikacijsku oznaku (16 B) – dulji je od 16 + 12 B.
    [Fact]
    public async Task CiphertextContainsNonceAndTag()
    {
        var ciphertext = await StoreCardAsync(factory.CreateClient(), CardNumber);

        Assert.True(Convert.FromBase64String(ciphertext).Length > 16 + 12,
            "Šifrat je prekratak da bi sadržavao nonce i autentikacijsku oznaku (tag).");
    }

    // Dio B: hardkodirani ključ "AkademijaKljuc16" u ECB načinu NE smije dešifrirati pohranjeni broj.
    [Fact]
    public async Task HardcodedKeyCannotDecryptStoredCard()
    {
        var ciphertext = Convert.FromBase64String(await StoreCardAsync(factory.CreateClient(), CardNumber));

        string? decrypted;
        try
        {
            using var aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("AkademijaKljuc16");
            decrypted = Encoding.UTF8.GetString(aes.DecryptEcb(ciphertext, PaddingMode.PKCS7));
        }
        catch (CryptographicException)
        {
            decrypted = null; // dešifriranje nije uspjelo – očekivano nakon popravka
        }

        Assert.NotEqual(CardNumber, decrypted);
    }

    private static async Task<Dictionary<string, string>> GetExportedHashesAsync(HttpClient client)
    {
        var export = await (await client.GetAsync("/api/lab06/customers/export")).ReadJsonAsync();
        return export.EnumerateArray().ToDictionary(
            e => e.GetProperty("username").GetString()!,
            e => e.GetProperty("passwordHash").GetString()!);
    }

    private static async Task<string> StoreCardAsync(HttpClient client, string cardNumber)
    {
        var response = await client.PostAsJsonAsync("/api/lab06/cards", new { cardNumber });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.ReadJsonAsync()).GetProperty("ciphertext").GetString()!;
    }
}
