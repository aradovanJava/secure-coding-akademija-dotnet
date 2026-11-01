namespace VulnShop.Tests.Labs.Lab03;

/// <summary>
/// Lab03 – sigurnosni testovi (SSRF).
///
/// Napomena: u testovima aplikacija radi na TestServeru (u memoriji, bez stvarnog TCP porta),
/// pa ranjivi kod ovdje ne može stvarno dohvatiti /internal/admin/secrets – zahtjev ne uspije
/// (502). Ispravan kod mora takav URL ODBITI PRIJE dohvata, s 400 Bad Request. Ručno (aplikacija
/// pokrenuta na http://localhost:5080) napad vraća tajne – vidi http/lab03.http.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab03")]
public sealed class Lab03SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Interna odredišta (loopback, IPv6 loopback, cloud metadata) moraju biti odbijena s 400.
    [Theory]
    [InlineData("http://127.0.0.1:5080/internal/admin/secrets")]
    [InlineData("http://localhost:5080/internal/admin/secrets")]
    [InlineData("http://[::1]:5080/internal/admin/secrets")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    public async Task InternalDestinationsAreRejected(string url)
    {
        var client = await factory.CreateClientAsAsync("ana", "Ana123!");

        var response = await client.GetAsync("/api/lab03/preview?url=" + Uri.EscapeDataString(url));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Sup3rTajn0!", body);
    }
}
