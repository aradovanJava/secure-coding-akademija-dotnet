namespace VulnShop.Tests.Labs.Lab11;

/// <summary>Lab11 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab11")]
public sealed class Lab11FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task LoginWithCorrectPasswordWorks()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab11/login", new { username = "ivana", password = "sunshine1" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task LoginWithWrongPasswordIsUnauthorized()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab11/login", new { username = "tomislav", password = "kriva" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
