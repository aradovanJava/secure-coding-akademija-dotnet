using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;

namespace VulnShop.Tests.Labs.Lab14;

/// <summary>
/// Lab14 – sigurnosni testovi (logiranje). Svaki test pokreće aplikaciju s vlastitim
/// <see cref="InMemoryLoggerProvider"/> i zatim provjerava što je zapisano u log.
/// </summary>
[Trait("Category", "Security")]
[Trait("Lab", "Lab14")]
public sealed class Lab14SecurityTests(VulnShopFactory factory) : IClassFixture<VulnShopFactory>
{
    // Lozinka se nikada ne smije pojaviti u logu.
    [Fact]
    public async Task PasswordIsNeverLogged()
    {
        var (app, logs) = CreateAppWithLogCapture();
        using var _ = app;

        await app.CreateClient().PostAsJsonAsync("/api/lab14/login",
            new { username = "ana", password = "MojaTajna!2026" });

        Assert.DoesNotContain(logs.Entries, e => e.Message.Contains("MojaTajna!2026"));
    }

    // Korisničko ime s \n ne smije stvoriti novi, krivotvoreni redak u logu (log injection).
    [Fact]
    public async Task NewlineInUsernameCannotForgeLogLine()
    {
        var (app, logs) = CreateAppWithLogCapture();
        using var _ = app;
        const string forged = "2026-11-02 10:00:00 INFO Login successful user=admin";

        await app.CreateClient().PostAsJsonAsync("/api/lab14/login",
            new { username = "ana\n" + forged, password = "kriva" });

        var lines = logs.Entries.SelectMany(e => e.Message.Split('\n', '\r'));
        Assert.DoesNotContain(lines, line => line.StartsWith(forged, StringComparison.Ordinal));
    }

    // Neuspjela prijava mora ostaviti sigurnosni događaj SECURITY_EVENT LOGIN_FAILED.
    [Fact]
    public async Task FailedLoginIsLoggedAsSecurityEvent()
    {
        var (app, logs) = CreateAppWithLogCapture();
        using var _ = app;

        await app.CreateClient().PostAsJsonAsync("/api/lab14/login", new { username = "marko", password = "kriva" });

        Assert.Contains(logs.Entries,
            e => e.Message.Contains("SECURITY_EVENT") && e.Message.Contains("LOGIN_FAILED"));
    }

    // Nakon 5 neuspjelih prijava za istog korisnika mora se pojaviti SECURITY_ALERT.
    [Fact]
    public async Task RepeatedFailuresRaiseSecurityAlert()
    {
        var (app, logs) = CreateAppWithLogCapture();
        using var _ = app;
        var client = app.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            await client.PostAsJsonAsync("/api/lab14/login", new { username = "admin", password = "pogadjam" + i });
        }

        Assert.Contains(logs.Entries, e => e.Message.Contains("SECURITY_ALERT"));
    }

    private (WebApplicationFactory<Program> App, InMemoryLoggerProvider Logs) CreateAppWithLogCapture()
    {
        var logs = new InMemoryLoggerProvider();
        var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging => logging.AddProvider(logs)));
        return (app, logs);
    }
}
