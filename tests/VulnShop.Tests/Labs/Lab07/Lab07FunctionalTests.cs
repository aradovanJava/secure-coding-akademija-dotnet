namespace VulnShop.Tests.Labs.Lab07;

/// <summary>Lab07 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab07")]
public sealed class Lab07FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task SearchFindsVisibleProduct()
    {
        var response = await factory.CreateClient().GetAsync("/api/lab07/products/search?q=Laptop");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.ReadJsonAsync();
        Assert.Equal(1, json.GetArrayLength());
        Assert.Equal("Laptop", json[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task LoginWithCorrectCredentialsWorks()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab07/login", new { username = "admin", password = "SuperTajna2026" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task LoginWithWrongPasswordFails()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab07/login", new { username = "admin", password = "kriva" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
