namespace VulnShop.Tests.Labs.Lab07;

/// <summary>Lab07 – sigurnosni testovi (SQL injection).</summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab07")]
public sealed class Lab07SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Klasični payload ' OR '1'='1' -- ne smije otkriti skriveni proizvod.
    [Theory]
    [InlineData("' OR '1'='1' --")]
    [InlineData("%' OR 1=1 --")]
    public async Task OrTautologyDoesNotRevealHiddenProduct(string payload)
    {
        var response = await factory.CreateClient()
            .GetAsync("/api/lab07/products/search?q=" + Uri.EscapeDataString(payload));

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Interni prototip X", body);
    }

    // UNION napad ne smije vratiti korisnička imena i lozinke iz tablice lab07_accounts.
    [Fact]
    public async Task UnionSelectDoesNotLeakAccounts()
    {
        const string payload = "%' UNION SELECT id, username, password, 0 FROM lab07_accounts --";

        var response = await factory.CreateClient()
            .GetAsync("/api/lab07/products/search?q=" + Uri.EscapeDataString(payload));

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.OK, HttpStatusCode.BadRequest });
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("SuperTajna2026", body);
        Assert.DoesNotContain("webshop", body);
    }

    // Komentar u korisničkom imenu (admin'--) ne smije zaobići provjeru lozinke.
    [Fact]
    public async Task CommentInUsernameDoesNotBypassLogin()
    {
        var response = await factory.CreateClient()
            .PostAsJsonAsync("/api/lab07/login", new { username = "admin'--", password = "bilo-sto" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
