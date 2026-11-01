namespace VulnShop.Tests.Labs.Lab15;

/// <summary>
/// Lab15 – sigurnosni testovi (rukovanje iznimnim situacijama).
/// Svaki test pokreće VLASTITU instancu aplikacije (svježa baza), jer mijenja salda.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab15")]
public sealed class Lab15SecurityTests
{
    // Nepoznata valuta + iznos iznad limita: transfer se ODBIJA (fail-closed), saldo nepromijenjen.
    [Fact]
    public async Task UnknownCurrencyFailsClosed()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana, "HR-ANA-001");

        var response = await ana.PostAsJsonAsync("/api/lab15/transfer", new
        {
            fromAccount = "HR-ANA-001", toAccount = "HR-MARKO-001", amount = "50000.00", currency = "XYZ",
        });

        Assert.InRange((int)response.StatusCode, 400, 499);
        Assert.Equal(before, await GetBalanceAsync(ana, "HR-ANA-001"));
    }

    // Transfer na nepostojeći račun: 4xx i terećenje se poništava (novac ne smije "nestati").
    [Fact]
    public async Task FailedCreditRollsBackDebit()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");
        var before = await GetBalanceAsync(ana, "HR-ANA-001");

        var response = await ana.PostAsJsonAsync("/api/lab15/transfer", new
        {
            fromAccount = "HR-ANA-001", toAccount = "HR-NEPOSTOJECI-999", amount = "100.00", currency = "EUR",
        });

        Assert.InRange((int)response.StatusCode, 400, 499);
        Assert.Equal(before, await GetBalanceAsync(ana, "HR-ANA-001"));
    }

    // Tijelo greške ne smije otkriti naziv klase iznimke ni SQL naredbu.
    [Fact]
    public async Task ErrorResponseDoesNotLeakInternals()
    {
        using var factory = new VulnShopFactory();
        var ana = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await ana.PostAsJsonAsync("/api/lab15/transfer", new
        {
            fromAccount = "HR-ANA-001", toAccount = "HR-NEPOSTOJECI-999", amount = "100.00", currency = "EUR",
        });

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Exception", body);
        Assert.DoesNotContain("UPDATE", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lab15_accounts", body);
    }

    private static async Task<decimal> GetBalanceAsync(HttpClient client, string accountNo)
    {
        var accounts = await (await client.GetAsync("/api/lab15/accounts")).ReadJsonAsync();
        return accounts.EnumerateArray()
            .Single(a => a.GetProperty("accountNo").GetString() == accountNo)
            .GetDecimalValue("balance");
    }
}
