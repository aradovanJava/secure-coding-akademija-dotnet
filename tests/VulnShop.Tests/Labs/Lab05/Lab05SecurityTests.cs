namespace VulnShop.Tests.Labs.Lab05;

/// <summary>
/// Lab05 – sigurnosni testovi (ranjiva ovisnost Newtonsoft.Json 12.0.3).
///
/// Važno: Microsoft.NET.Test.Sdk u testni proces povlači Newtonsoft.Json 13.x, pa se pad procesa
/// (StackOverflow) iz verzije 12.0.3 NE MOŽE reproducirati unutar testova. Zato provjeravamo:
///  (a) s kojom je verzijom paketa API projekt KOMPAJLIRAN (12.0.3 → AssemblyVersion 12.0.0.0),
///  (b) da preduboki JSON vraća 400 Bad Request (kontrolirano odbijanje), a ne 500 ili pad.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab05")]
public sealed class Lab05SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // API projekt mora biti preveden s Newtonsoft.Json 13.x ili novijim (ispravak GHSA-5crp-9r3c-p9vr).
    [Fact]
    public void ApiIsCompiledAgainstPatchedNewtonsoftJson()
    {
        var reference = typeof(Program).Assembly.GetReferencedAssemblies()
            .Single(a => a.Name == "Newtonsoft.Json");

        Assert.True(reference.Version!.Major >= 13,
            $"VulnShop.Api koristi Newtonsoft.Json {reference.Version} – potrebna je verzija 13.0.1 ili novija.");
    }

    // JSON dubine 200 mora biti odbijen s 400 (eksplicitni MaxDepth + obrada JsonReaderException).
    [Fact]
    public async Task DeeplyNestedJsonIsRejectedWithBadRequest()
    {
        var deepJson = new string('[', 200) + new string(']', 200);

        var response = await factory.CreateClient().PostRawJsonAsync("/api/lab05/import", deepJson);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
