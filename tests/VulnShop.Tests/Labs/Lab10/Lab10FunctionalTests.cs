namespace VulnShop.Tests.Labs.Lab10;

/// <summary>Lab10 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab10")]
public sealed class Lab10FunctionalTests
{
    // Ispravna kupnja (2 × kabel po 9.99) umanjuje stanje točno za 19.98.
    [Fact]
    public async Task ValidCheckoutChargesExactAmount()
    {
        using var factory = new VulnShopFactory();
        var marko = await factory.CreateClientAsAsync("marko", "Marko123!");
        var before = await GetBalanceAsync(marko);

        var response = await marko.PostAsJsonAsync("/api/lab10/checkout", new
        {
            items = new[] { new { productId = 3, quantity = 2, unitPrice = 9.99m } },
            couponCodes = Array.Empty<string>(),
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before - 19.98m, await GetBalanceAsync(marko));
    }

    // Jedan kupon AKADEMIJA10 daje 10 % popusta (99.00 → 89.10).
    [Fact]
    public async Task SingleCouponGivesTenPercentDiscount()
    {
        using var factory = new VulnShopFactory();
        var admin = await factory.CreateClientAsAsync("admin", "Admin123!");
        var before = await GetBalanceAsync(admin);

        var response = await admin.PostAsJsonAsync("/api/lab10/checkout", new
        {
            items = new[] { new { productId = 2, quantity = 1, unitPrice = 99.00m } },
            couponCodes = new[] { "AKADEMIJA10" },
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before - 89.10m, await GetBalanceAsync(admin));
    }

    private static async Task<decimal> GetBalanceAsync(HttpClient client) =>
        (await (await client.GetAsync("/api/lab10/wallet")).ReadJsonAsync()).GetDecimalValue("balance");
}
