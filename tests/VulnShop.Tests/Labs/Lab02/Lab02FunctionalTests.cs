namespace VulnShop.Tests.Labs.Lab02;

/// <summary>Lab02 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab02")]
public sealed class Lab02FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Korisnica mijenja prikazno ime i e-poštu – dopuštena polja.
    [Fact]
    public async Task UserCanUpdateDisplayNameAndEmail()
    {
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await ana.PutAsJsonAsync("/api/lab02/profile",
            new { displayName = "Ana Nova", email = "ana.nova@akademija.hr" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var profile = await (await ana.GetAsync("/api/lab02/profile")).ReadJsonAsync();
        Assert.Equal("Ana Nova", profile.GetProperty("displayName").GetString());
        Assert.Equal("ana.nova@akademija.hr", profile.GetProperty("email").GetString());
        Assert.Equal("USER", profile.GetProperty("role").GetString());
    }

    // Administrator smije vidjeti popis korisnika.
    [Fact]
    public async Task AdminCanListUsers()
    {
        var admin = await factory.CreateClientAsAsync("admin", "Admin123!");

        var response = await admin.GetAsync("/api/lab02/admin/users");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
