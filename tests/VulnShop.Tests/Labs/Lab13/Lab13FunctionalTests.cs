namespace VulnShop.Tests.Labs.Lab13;

/// <summary>Lab13 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab13")]
public sealed class Lab13FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Legitimna košarica s dvije stavke uspješno se uvozi.
    [Fact]
    public async Task LegitimateCartIsImported()
    {
        const string cart = """
            {"owner":"ana","items":[
              {"productId":1,"name":"Laptop","quantity":1},
              {"productId":2,"name":"Slusalice","quantity":2}
            ]}
            """;

        var response = await factory.CreateClient().PostRawJsonAsync("/api/lab13/cart/import", cart);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, (await response.ReadJsonAsync()).GetProperty("itemCount").GetInt32());
    }
}
