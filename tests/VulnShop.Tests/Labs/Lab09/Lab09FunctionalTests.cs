namespace VulnShop.Tests.Labs.Lab09;

/// <summary>Lab09 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab09")]
public sealed class Lab09FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Ispravna IP adresa se prihvaća (ne ovisimo o tome je li ping stvarno uspio).
    [Fact]
    public async Task ValidHostIsAccepted()
    {
        var response = await factory.CreateClient().GetAsync("/api/lab09/ping?host=127.0.0.1");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
