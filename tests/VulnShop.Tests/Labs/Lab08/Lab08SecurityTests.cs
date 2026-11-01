namespace VulnShop.Tests.Labs.Lab08;

/// <summary>Lab08 – sigurnosni testovi (XSS). Svaki test koristi vlastiti productId.</summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab08")]
public sealed class Lab08SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Reflektirani XSS: skripta iz parametra q mora biti kodirana (&lt;script&gt;).
    [Fact]
    public async Task ReflectedScriptIsEncoded()
    {
        var response = await factory.CreateClient()
            .GetAsync("/lab08/search?q=" + Uri.EscapeDataString("<script>alert(1)</script>"));

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>alert(1)</script>", body);
        Assert.Contains("&lt;script&gt;", body);
    }

    // Pohranjeni XSS: HTML iz recenzije mora biti kodiran prilikom prikaza.
    [Fact]
    public async Task StoredReviewHtmlIsEncoded()
    {
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/lab08/reviews",
            new { productId = 801, author = "Napadač", text = "<img src=x onerror=alert('XSS')>" });

        var body = await (await client.GetAsync("/lab08/products/801/reviews")).Content.ReadAsStringAsync();

        Assert.DoesNotContain("<img src=x onerror=", body);
        Assert.Contains("&lt;img", body);
    }

    // HTML stranice šalju Content-Security-Policy sa script-src (druga linija obrane).
    [Fact]
    public async Task HtmlPagesSendContentSecurityPolicy()
    {
        var response = await factory.CreateClient().GetAsync("/lab08/search?q=test");

        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var values),
            "Nedostaje zaglavlje Content-Security-Policy.");
        Assert.Contains("script-src", values!.Single());
    }
}
