namespace VulnShop.Tests.Labs.Lab11;

/// <summary>
/// Lab11 – sigurnosni testovi (enumeracija korisnika i brute force).
/// Test zaključavanja koristi zasebnog korisnika "lockme" kako ne bi utjecao na druge testove.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab11")]
public sealed class Lab11SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Nepostojeći korisnik i kriva lozinka moraju dati ISTI status i ISTO tijelo odgovora.
    [Fact]
    public async Task UnknownUserAndWrongPasswordLookTheSame()
    {
        var client = factory.CreateClient();

        var unknownUser = await client.PostAsJsonAsync("/api/lab11/login",
            new { username = "nepostojeci_korisnik", password = "nesto123" });
        var wrongPassword = await client.PostAsJsonAsync("/api/lab11/login",
            new { username = "tomislav", password = "nesto123" });

        Assert.Equal(unknownUser.StatusCode, wrongPassword.StatusCode);
        Assert.Equal(await unknownUser.Content.ReadAsStringAsync(), await wrongPassword.Content.ReadAsStringAsync());
    }

    // Nakon 5 neuspjelih pokušaja račun je zaključan: čak i ispravna lozinka vraća 429.
    [Fact]
    public async Task AccountIsLockedAfterFiveFailedAttempts()
    {
        var client = factory.CreateClient();
        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync("/api/lab11/login", new { username = "lockme", password = "kriva" + i });
        }

        var response = await client.PostAsJsonAsync("/api/lab11/login",
            new { username = "lockme", password = "Lock!Me2026" });

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
    }
}
