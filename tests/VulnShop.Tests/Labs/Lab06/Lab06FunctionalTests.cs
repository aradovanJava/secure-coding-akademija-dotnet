namespace VulnShop.Tests.Labs.Lab06;

/// <summary>Lab06 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab06")]
public sealed class Lab06FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Registracija pa prijava točnom lozinkom uspijeva, krivom ne.
    [Fact]
    public async Task RegisterThenLoginWorks()
    {
        var client = factory.CreateClient();
        var user = "kupac_" + Guid.NewGuid().ToString("N")[..8];

        var register = await client.PostAsJsonAsync("/api/lab06/register", new { username = user, password = "Zima2026!" });
        var good = await client.PostAsJsonAsync("/api/lab06/login", new { username = user, password = "Zima2026!" });
        var bad = await client.PostAsJsonAsync("/api/lab06/login", new { username = user, password = "kriva" });

        Assert.Equal(HttpStatusCode.OK, register.StatusCode);
        Assert.Equal(HttpStatusCode.OK, good.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
    }

    // Seed kupac se može prijaviti (seed mora biti hashiran istom metodom kao i provjera).
    [Fact]
    public async Task SeedCustomerCanLogin()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab06/login", new { username = "petra", password = "password" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // Maskirani prikaz kartice prikazuje samo zadnje 4 znamenke.
    [Fact]
    public async Task MaskedCardShowsLastFourDigits()
    {
        var client = factory.CreateClient();
        var stored = await (await client.PostAsJsonAsync("/api/lab06/cards", new { cardNumber = "5555444433331111" }))
            .ReadJsonAsync();
        var id = stored.GetProperty("id").GetInt64();

        var masked = await (await client.GetAsync($"/api/lab06/cards/{id}/masked")).ReadJsonAsync();

        Assert.Equal("**** **** **** 1111", masked.GetProperty("masked").GetString());
    }
}
