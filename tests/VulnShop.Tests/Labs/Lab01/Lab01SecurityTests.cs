namespace VulnShop.Tests.Labs.Lab01;

/// <summary>
/// Lab01 – sigurnosni testovi (IDOR). Na ranjivom kodu (grana main) PADAJU,
/// nakon ispravnog popravka PROLAZE.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab01")]
public sealed class Lab01SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Ana ne smije pročitati Markovu narudžbu 1003. Očekujemo 404 – ne otkrivamo ni da narudžba postoji.
    [Fact]
    public async Task UserCannotReadOrderOfAnotherUser()
    {
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await ana.GetAsync("/api/lab01/orders/1003");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Savska 10", body); // Markova adresa ne smije procuriti
    }

    // Ni administratorova narudžba (1004) nije dostupna običnom korisniku.
    [Fact]
    public async Task UserCannotReadOrderOfAdmin()
    {
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await ana.GetAsync("/api/lab01/orders/1004");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
