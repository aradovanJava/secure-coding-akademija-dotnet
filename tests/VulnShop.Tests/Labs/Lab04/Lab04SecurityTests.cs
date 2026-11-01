using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace VulnShop.Tests.Labs.Lab04;

/// <summary>
/// Lab04 – sigurnosni testovi (sigurnosna konfiguracija).
/// Aplikacija se ovdje pokreće u okruženju <c>Production</c> – provjeravamo kako se ponaša
/// produkcijska instalacija (u Developmentu su detaljne greške i debug alati očekivani).
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab04")]
public sealed class Lab04SecurityTests : IClassFixture<VulnShopFactory>, IDisposable
{
    private readonly WebApplicationFactory<Program> _production;

    public Lab04SecurityTests(VulnShopFactory factory)
    {
        _production = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
    }

    public void Dispose() => _production.Dispose();

    // Debug endpoint s konfiguracijom ne smije biti dostupan u produkciji niti otkriti tajnu.
    [Fact]
    public async Task DebugConfigEndpointIsNotExposed()
    {
        var response = await _production.CreateClient().GetAsync("/api/lab04/debug/config");

        Assert.Contains(response.StatusCode,
            new[] { HttpStatusCode.NotFound, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("sk_live_akademija_123", body);
    }

    // Greška vraća 500 s generičkom porukom – bez naziva klasa, namespacea i stack tracea.
    [Fact]
    public async Task ErrorResponseDoesNotLeakStackTrace()
    {
        var response = await _production.CreateClient().GetAsync("/api/lab04/crash");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("VulnShop.Api", body);
        Assert.DoesNotContain("Exception", body);
        Assert.DoesNotContain("   at ", body);
        Assert.DoesNotContain("db.interno.local", body);
    }

    // CORS preflight sa stranog origina ne smije dobiti Access-Control-Allow-Origin.
    [Fact]
    public async Task CorsDoesNotAllowArbitraryOrigin()
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/lab04/ping");
        request.Headers.Add("Origin", "https://evil.example");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await _production.CreateClient().SendAsync(request);

        var allowed = response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values)
            ? values.ToArray()
            : Array.Empty<string>();
        Assert.DoesNotContain("https://evil.example", allowed);
        Assert.DoesNotContain("*", allowed);
    }

    // Odgovori imaju osnovna sigurnosna zaglavlja.
    [Fact]
    public async Task SecurityHeadersArePresent()
    {
        var response = await _production.CreateClient().GetAsync("/api/lab04/ping");

        Assert.True(response.Headers.TryGetValues("X-Content-Type-Options", out var nosniff),
            "Nedostaje zaglavlje X-Content-Type-Options.");
        Assert.Equal("nosniff", nosniff!.Single());
        Assert.True(response.Headers.TryGetValues("X-Frame-Options", out var frameOptions),
            "Nedostaje zaglavlje X-Frame-Options.");
        Assert.Equal("DENY", frameOptions!.Single());
    }
}
