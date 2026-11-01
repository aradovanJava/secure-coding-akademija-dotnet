namespace VulnShop.Tests.Labs.Lab08;

/// <summary>Lab08 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab08")]
public sealed class Lab08FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task SearchPageShowsQuery()
    {
        var response = await factory.CreateClient().GetAsync("/lab08/search?q=Laptop");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Rezultati pretrage za: Laptop", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ReviewIsStoredAndShown()
    {
        var client = factory.CreateClient();

        var post = await client.PostAsJsonAsync("/api/lab08/reviews",
            new { productId = 901, author = "Ivana", text = "Odlican proizvod, preporucujem." });
        var page = await client.GetAsync("/lab08/products/901/reviews");

        Assert.Equal(HttpStatusCode.OK, post.StatusCode);
        var body = await page.Content.ReadAsStringAsync();
        Assert.Contains("Ivana", body);
        Assert.Contains("Odlican proizvod, preporucujem.", body);
    }
}
