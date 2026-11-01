namespace VulnShop.Tests.Labs.Lab04;

/// <summary>Lab04 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab04")]
public sealed class Lab04FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Health check ostaje dostupan (koristi ga npr. load balancer).
    [Fact]
    public async Task HealthEndpointWorks()
    {
        var response = await factory.CreateClient().GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PingWorks()
    {
        var response = await factory.CreateClient().GetAsync("/api/lab04/ping");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
