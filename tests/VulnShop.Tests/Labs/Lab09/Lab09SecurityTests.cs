namespace VulnShop.Tests.Labs.Lab09;

/// <summary>Lab09 – sigurnosni testovi (OS command injection).</summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab09")]
public sealed class Lab09SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Ulančana naredba (&) mora biti odbijena s 400 i NE smije se izvršiti.
    [Fact]
    public async Task ChainedCommandIsRejected()
    {
        var response = await factory.CreateClient()
            .GetAsync("/api/lab09/ping?host=" + Uri.EscapeDataString("127.0.0.1 & echo PWNED_LAB09"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("PWNED_LAB09", await response.Content.ReadAsStringAsync());
    }

    // Odvajanje naredbi točka-zarezom (;) mora biti odbijeno s 400.
    [Fact]
    public async Task SemicolonCommandIsRejected()
    {
        var response = await factory.CreateClient()
            .GetAsync("/api/lab09/ping?host=" + Uri.EscapeDataString("127.0.0.1;id"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
