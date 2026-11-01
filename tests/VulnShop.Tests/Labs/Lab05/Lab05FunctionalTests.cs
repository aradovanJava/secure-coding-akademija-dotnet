namespace VulnShop.Tests.Labs.Lab05;

/// <summary>Lab05 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab05")]
public sealed class Lab05FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Običan JSON se uvozi i vraća broj elemenata i dubinu.
    [Fact]
    public async Task ImportOfRegularJsonWorks()
    {
        var response = await factory.CreateClient()
            .PostRawJsonAsync("/api/lab05/import", """{"proizvodi":[{"naziv":"Laptop"},{"naziv":"Miš"}]}""");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.ReadJsonAsync();
        Assert.Equal(6, json.GetProperty("elements").GetInt32());
        Assert.Equal(4, json.GetProperty("depth").GetInt32());
    }
}
