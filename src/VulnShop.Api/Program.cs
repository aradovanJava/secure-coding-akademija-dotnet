using System.Text.Encodings.Web;
using System.Text.Unicode;
using VulnShop.Api.Common;
using VulnShop.Api.Labs.Lab04;
using VulnShop.Api.Labs.Lab12;
using VulnShop.Api.Labs.Lab15;

// ============================================================================
//  VulnShop Akademija – NAMJERNO RANJIVA web aplikacija za vježbe sigurnog
//  programiranja. Pokrećite je ISKLJUČIVO lokalno (http://localhost:5080)!
// ============================================================================

var builder = WebApplication.CreateBuilder(args);

// Hrvatski znakovi (č ć đ š ž) u JSON odgovorima ostaju čitljivi; HTML-osjetljivi
// znakovi (< > & ' ") i dalje se kodiraju.
var jsonEncoder = JavaScriptEncoder.Create(
    UnicodeRanges.BasicLatin, UnicodeRanges.Latin1Supplement, UnicodeRanges.LatinExtendedA);
builder.Services
    .AddControllers()
    .AddJsonOptions(options => options.JsonSerializerOptions.Encoder = jsonEncoder);
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Encoder = jsonEncoder);

builder.Services.AddHealthChecks();
builder.Services.AddMemoryCache();

// Zajednička infrastruktura (baza, prijava) – implementirana ispravno, nije dio vježbi.
builder.Services.AddSingleton<Db>();
builder.Services.AddSingleton<TokenStore>();
builder.Services.AddSingleton<UserService>();

// Servisi pojedinih vježbi.
builder.Services.AddSingleton<JwtService>();     // Lab12
builder.Services.AddSingleton<LimitService>();   // Lab15
builder.Services.AddLab04(builder.Configuration); // Lab04 (CORS)

var app = builder.Build();

// Shema + početni podaci (svaka instanca aplikacije dobiva svježu in-memory bazu).
DbInitializer.Initialize(app.Services.GetRequiredService<Db>());

app.UseLab04ErrorHandling();    // Lab04 – rukovanje greškama
app.UseLab04SecurityHeaders();  // Lab04 – sigurnosna HTTP zaglavlja
app.UseCors();                  // Lab04 – CORS politika (vidi Lab04Setup.AddLab04)

app.UseMiddleware<BearerTokenMiddleware>();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();

/// <summary>Omogućuje <c>WebApplicationFactory&lt;Program&gt;</c> u integracijskim testovima.</summary>
public partial class Program { }
