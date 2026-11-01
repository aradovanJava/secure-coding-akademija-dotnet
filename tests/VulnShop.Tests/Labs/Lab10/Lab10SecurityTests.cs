namespace VulnShop.Tests.Labs.Lab10;

/// <summary>
/// Lab10 – sigurnosni testovi (poslovna logika).
/// Svaki test pokreće VLASTITU instancu aplikacije (svježa baza), jer mijenja stanje novčanika.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab10")]
public sealed class Lab10SecurityTests
{
    // Negativna količina mora biti odbijena (400), a stanje novčanika nepromijenjeno.
    [Fact]
    public async Task NegativeQuantityIsRejected()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana);

        var response = await ana.PostAsJsonAsync("/api/lab10/checkout", new
        {
            items = new[] { new { productId = 1, quantity = -5, unitPrice = 899.00m } },
            couponCodes = Array.Empty<string>(),
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await GetBalanceAsync(ana));
    }

    // Cijena iz zahtjeva se ignorira: laptop se naplaćuje 899.00 (ili se zahtjev odbija) – nikad 0.01.
    [Fact]
    public async Task ClientSuppliedPriceIsIgnored()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana);

        var response = await ana.PostAsJsonAsync("/api/lab10/checkout", new
        {
            items = new[] { new { productId = 1, quantity = 1, unitPrice = 0.01m } },
            couponCodes = Array.Empty<string>(),
        });

        var charged = before - await GetBalanceAsync(ana);
        if (response.StatusCode == HttpStatusCode.OK)
        {
            Assert.Equal(899.00m, charged);
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0m, charged);
        }
    }

    // Isti kupon tri puta: zahtjev se odbija ili se popust (10 %) primjenjuje samo jednom.
    [Fact]
    public async Task CouponCannotBeStacked()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana);

        var response = await ana.PostAsJsonAsync("/api/lab10/checkout", new
        {
            items = new[] { new { productId = 1, quantity = 1, unitPrice = 899.00m } },
            couponCodes = new[] { "AKADEMIJA10", "AKADEMIJA10", "AKADEMIJA10" },
        });

        var charged = before - await GetBalanceAsync(ana);
        if (response.StatusCode == HttpStatusCode.OK)
        {
            Assert.Equal(809.10m, charged); // 899.00 − 10 %
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(0m, charged);
        }
    }

    private static async Task<decimal> GetBalanceAsync(HttpClient client) =>
        (await (await client.GetAsync("/api/lab10/wallet")).ReadJsonAsync()).GetDecimalValue("balance");
}
