using System.Text.Json.Nodes;

namespace VulnShop.Tests.Labs.Lab13;

/// <summary>
/// Lab13 – sigurnosni testovi (nesigurna deserijalizacija).
/// Test sam gradi napadni JSON s "$type" koji traži gadget klasu DiagnosticsTask; gadget bi
/// zapisao bezopasnu marker datoteku u privremeni direktorij. Datoteka NE smije nastati.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab13")]
public sealed class Lab13SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task TypeNamePayloadIsRejectedAndGadgetDoesNotRun()
    {
        var markerPath = Path.Combine(Path.GetTempPath(), $"lab13-marker-{Guid.NewGuid():N}.txt");
        // "$type" mora biti prvo svojstvo – JsonObject čuva redoslijed umetanja.
        var payload = new JsonObject
        {
            ["$type"] = "VulnShop.Api.Labs.Lab13.DiagnosticsTask, VulnShop.Api",
            ["ReportPath"] = markerPath,
            ["Content"] = "PWNED",
        }.ToJsonString();

        try
        {
            var response = await factory.CreateClient().PostRawJsonAsync("/api/lab13/cart/import", payload);

            Assert.False(File.Exists(markerPath), "Gadget se izvršio tijekom deserijalizacije i zapisao datoteku.");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        finally
        {
            File.Delete(markerPath);
        }
    }
}
