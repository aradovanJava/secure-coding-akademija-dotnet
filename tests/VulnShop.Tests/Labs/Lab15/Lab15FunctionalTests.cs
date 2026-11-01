namespace VulnShop.Tests.Labs.Lab15;

/// <summary>Lab15 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab15")]
public sealed class Lab15FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Ispravan transfer od 100 EUR uspijeva; saldo pošiljatelja manji je točno za 100 (mjerimo razliku).
    [Fact]
    public async Task ValidTransferMovesMoney()
    {
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana, "HR-ANA-001");

        var response = await ana.PostAsJsonAsync("/api/lab15/transfer", new
        {
            fromAccount = "HR-ANA-001", toAccount = "HR-MARKO-001", amount = "100.00", currency = "EUR",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before - 100.00m, await GetBalanceAsync(ana, "HR-ANA-001"));
    }

    [Fact]
    public async Task AnonymousRequestIsRejected()
    {
        var response = await factory.CreateClient().GetAsync("/api/lab15/accounts");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<decimal> GetBalanceAsync(HttpClient client, string accountNo)
    {
        var accounts = await (await client.GetAsync("/api/lab15/accounts")).ReadJsonAsync();
        return accounts.EnumerateArray()
            .Single(a => a.GetProperty("accountNo").GetString() == accountNo)
            .GetDecimalValue("balance");
    }
}
