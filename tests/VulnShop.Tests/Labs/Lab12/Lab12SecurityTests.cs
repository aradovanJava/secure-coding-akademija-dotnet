using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using VulnShop.Api.Labs.Lab12;

namespace VulnShop.Tests.Labs.Lab12;

/// <summary>Lab12 – sigurnosni testovi (JWT propusti).</summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab12")]
public sealed class Lab12SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    private static readonly long FutureExp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();

    // Token s "alg":"none" i bez potpisa mora biti odbijen.
    [Fact]
    public async Task AlgNoneTokenIsRejected()
    {
        var token = B64("""{"alg":"none","typ":"JWT"}""") + "." +
                    B64($$"""{"sub":"napadac","role":"ADMIN","exp":{{FutureExp}}}""") + ".";

        var response = await SendWithTokenAsync("/api/lab12/admin", token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // Token potpisan slabom tajnom "secret123" (iz rječnika) mora biti odbijen.
    [Fact]
    public async Task TokenSignedWithWeakSecretIsRejected()
    {
        var signingInput = B64("""{"alg":"HS256","typ":"JWT"}""") + "." +
                           B64($$"""{"sub":"napadac","role":"ADMIN","exp":{{FutureExp}}}""");
        var signature = Base64Url.Encode(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes("secret123"), Encoding.UTF8.GetBytes(signingInput)));

        var response = await SendWithTokenAsync("/api/lab12/admin", signingInput + "." + signature);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // Istekli token (izrađen ispravnim ključem kroz JwtService) mora biti odbijen.
    [Fact]
    public async Task ExpiredTokenIsRejected()
    {
        var jwt = factory.Services.GetRequiredService<JwtService>();
        var expired = jwt.CreateToken("ana", "USER", DateTimeOffset.UtcNow.AddMinutes(-5));

        var response = await SendWithTokenAsync("/api/lab12/me", expired);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private async Task<HttpResponseMessage> SendWithTokenAsync(string url, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await factory.CreateClient().SendAsync(request);
    }

    private static string B64(string json) => Base64Url.Encode(Encoding.UTF8.GetBytes(json));
}
