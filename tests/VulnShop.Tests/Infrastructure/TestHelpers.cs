using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace VulnShop.Tests.Infrastructure;

/// <summary>Pomoćne metode za testove: prijava, slanje JSON-a, čitanje odgovora.</summary>
public static class TestHelpers
{
    /// <summary>Prijava preko zajedničkog <c>POST /api/auth/login</c>; vraća Bearer token.</summary>
    public static async Task<string> LoginAsync(this HttpClient client, string username, string password)
    {
        var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.ReadJsonAsync();
        return json.GetProperty("token").GetString()!;
    }

    /// <summary>Stvara klijenta koji svakom zahtjevu dodaje zaglavlje Authorization: Bearer.</summary>
    public static async Task<HttpClient> CreateClientAsAsync(
        this Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> factory, string username, string password)
    {
        var client = factory.CreateClient();
        var token = await client.LoginAsync(username, password);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public static async Task<JsonElement> ReadJsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(text);
        return document.RootElement.Clone();
    }

    /// <summary>Šalje sirovi tekst kao tijelo zahtjeva s Content-Type: application/json.</summary>
    public static Task<HttpResponseMessage> PostRawJsonAsync(this HttpClient client, string url, string json) =>
        client.PostAsync(url, new StringContent(json, Encoding.UTF8, "application/json"));

    public static decimal GetDecimalValue(this JsonElement element, string property) =>
        element.GetProperty(property).GetDecimal();
}
