namespace VulnShop.Tests.Labs.Lab02;

/// <summary>
/// Lab02 – sigurnosni testovi (mass assignment / eskalacija privilegija).
/// Koriste korisnika marko (funkcionalni testovi koriste anu i admina).
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab02")]
public sealed class Lab02SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Polje "role" u tijelu zahtjeva mora se ignorirati (ili odbiti) – uloga ostaje USER.
    [Fact]
    public async Task RoleFieldInProfileUpdateIsIgnored()
    {
        var marko = await factory.CreateClientAsAsync("marko", "Marko123!");

        await marko.PutAsJsonAsync("/api/lab02/profile",
            new { displayName = "Marko", email = "m@x.hr", role = "ADMIN" });

        var profile = await (await marko.GetAsync("/api/lab02/profile")).ReadJsonAsync();
        Assert.Equal("USER", profile.GetProperty("role").GetString());
    }

    // Nakon pokušaja eskalacije marko i dalje NE smije pristupiti administratorskom popisu.
    [Fact]
    public async Task UserCannotEscalateToAdminEndpoint()
    {
        var marko = await factory.CreateClientAsAsync("marko", "Marko123!");

        await marko.PutAsJsonAsync("/api/lab02/profile",
            new { displayName = "Marko", email = "m@x.hr", role = "ADMIN" });
        var response = await marko.GetAsync("/api/lab02/admin/users");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
