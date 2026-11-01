using System.Net.Http.Headers;

namespace VulnShop.Tests.Labs.Lab12;

/// <summary>Lab12 – funkcionalni testovi. Prolaze i prije i nakon popravka.</summary>
[Trait("Category", "Functional")]
[Trait("Lab", "Lab12")]
public sealed class Lab12FunctionalTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    [Fact]
    public async Task LoginThenMeReturnsClaims()
    {
        var client = await LoginAsync("ana", "Ana123!");

        var response = await client.GetAsync("/api/lab12/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.ReadJsonAsync();
        Assert.Equal("ana", json.GetProperty("sub").GetString());
        Assert.Equal("USER", json.GetProperty("role").GetString());
    }

    [Fact]
    public async Task UserCannotAccessAdmin()
    {
        var client = await LoginAsync("ana", "Ana123!");

        var response = await client.GetAsync("/api/lab12/admin");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AdminCanAccessAdmin()
    {
        var client = await LoginAsync("admin", "Admin123!");

        var response = await client.GetAsync("/api/lab12/admin");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<HttpClient> LoginAsync(string username, string password)
    {
        var client = factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/lab12/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var token = (await login.ReadJsonAsync()).GetProperty("token").GetString();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }
}
