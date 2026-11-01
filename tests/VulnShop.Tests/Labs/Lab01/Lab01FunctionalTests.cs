namespace VulnShop.Tests.Labs.Lab01;

/// <summary>Lab01 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab01")]
public sealed class Lab01FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Vlasnica vidi svoju narudžbu.
    [Fact]
    public async Task OwnerCanReadOwnOrder()
    {
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await ana.GetAsync("/api/lab01/orders/1001");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.ReadJsonAsync();
        Assert.Equal(1001, json.GetProperty("id").GetInt64());
        Assert.Equal("ana", json.GetProperty("owner").GetString());
    }

    // Administrator smije vidjeti svaku narudžbu.
    [Fact]
    public async Task AdminCanReadAnyOrder()
    {
        var admin = await factory.CreateClientAsAsync("admin", "Admin123!");

        var response = await admin.GetAsync("/api/lab01/orders/1003");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // Bez tokena nema pristupa.
    [Fact]
    public async Task AnonymousRequestIsRejected()
    {
        var response = await factory.CreateClient().GetAsync("/api/lab01/orders/1001");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
