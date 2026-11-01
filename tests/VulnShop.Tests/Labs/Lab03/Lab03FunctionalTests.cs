namespace VulnShop.Tests.Labs.Lab03;

/// <summary>Lab03 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab03")]
public sealed class Lab03FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Nepodržana shema (ftp://) ne smije uspjeti (ranjivi kod vraća 502, ispravljeni 400).
    [Fact]
    public async Task UnsupportedSchemeIsNotFetched()
    {
        var client = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await client.GetAsync("/api/lab03/preview?url=" + Uri.EscapeDataString("ftp://example.com/file.txt"));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    // Bez tokena nema pristupa.
    [Fact]
    public async Task AnonymousRequestIsRejected()
    {
        var response = await factory.CreateClient()
            .GetAsync("/api/lab03/preview?url=" + Uri.EscapeDataString("https://example.com"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
