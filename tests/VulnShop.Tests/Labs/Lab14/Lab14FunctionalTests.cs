namespace VulnShop.Tests.Labs.Lab14;

/// <summary>Lab14 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab14")]
public sealed class Lab14FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task LoginWithCorrectPasswordWorks()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab14/login", new { username = "ana", password = "Ana123!" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task LoginWithWrongPasswordIsUnauthorized()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab14/login", new { username = "ana", password = "kriva" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
