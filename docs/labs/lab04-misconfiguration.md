# Lab04 – Sigurnosno pogrešna konfiguracija

> **OWASP Top 10:2025:** A02 Security Misconfiguration · **CWE:** CWE-16 (Configuration), CWE-209
> (Generation of Error Message Containing Sensitive Information), CWE-942 (Permissive Cross-domain Policy),
> CWE-693 (Protection Mechanism Failure) · **Endpointi:** `GET /api/lab04/ping`, `/api/lab04/crash`,
> `/api/lab04/debug/config`, `/health` · **Zahtjevi:** `http/lab04.http`

## 1. Cilj vježbe

Kod može biti ispravan, a aplikacija svejedno ranjiva zbog **konfiguracije**: debug endpoint koji otkriva
tajne, detaljne poruke grešaka u produkciji, preširoka CORS politika i nedostatak sigurnosnih zaglavlja.
Naučit ćete razlikovati razvojnu i produkcijsku konfiguraciju i "otvrdnuti" (*hardening*) aplikaciju.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Konfiguracija cjevovoda | `src/VulnShop.Api/Labs/Lab04/Lab04Setup.cs` – `AddLab04` (CORS), `UseLab04ErrorHandling`, `UseLab04SecurityHeaders` |
| Endpointi | `src/VulnShop.Api/Labs/Lab04/Lab04Controller.cs` – `Ping`, `Crash`, `DebugConfig` |
| Poziv iz aplikacije | `src/VulnShop.Api/Program.cs` (`AddLab04`, `UseLab04ErrorHandling`, `UseLab04SecurityHeaders`, `UseCors`) |
| Tajna / allowlista | `src/VulnShop.Api/appsettings.json` – `Payment:ApiKey`, `Lab04:AllowedOrigins` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab04/Lab04SecurityTests.cs` (pokreću aplikaciju u okruženju **Production**), `Lab04FunctionalTests.cs` |

## 3. Opis ranjivosti

Na grani `main`:

1. **`/api/lab04/debug/config`** vraća *sve* ključeve konfiguracije – uključujući `Payment:ApiKey`
   (analogno Spring Boot `/actuator/env`). Dostupan je bez prijave, u svakom okruženju.
2. **`UseDeveloperExceptionPage()` uvijek**, i u produkciji: greška vraća stack trace, nazive klasa i
   namespaceova, putanje datoteka i poruke s internim podacima (host baze, korisnik). Napadaču je to karta aplikacije.
3. **CORS** `SetIsOriginAllowed(_ => true).AllowCredentials()`: svaka web stranica na internetu može, u
   pregledniku prijavljene žrtve, slati zahtjeve s njezinim kolačićima i **čitati odgovore**.
4. **Bez sigurnosnih zaglavlja:** nema `X-Content-Type-Options: nosniff` (MIME sniffing),
   `X-Frame-Options: DENY` (clickjacking), `Content-Security-Policy`, `Referrer-Policy`.

Primjeri iz prakse: izloženi Spring Boot Actuator / `.env` / `phpinfo()` endpointi redovito su izvor
procurjelih ključeva za oblak; detaljne poruke grešaka olakšavaju SQL injection i otkrivaju verzije biblioteka.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju **u produkcijskom načinu**, kako biste vidjeli što bi vidio napadač na stvarnom poslužitelju:

```bash
dotnet run --project src/VulnShop.Api --launch-profile http-production
```

(VS 2026 / Rider: odaberite profil **http-production**; VS Code: konfiguracija *VulnShop.Api – Production način (Lab04)*.)

1. **1)** `GET /api/lab04/ping` – u zaglavljima odgovora nema `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`.
2. **2)** `GET /api/lab04/debug/config` – u odgovoru je `"Payment:ApiKey": "sk_live_akademija_123"`.
3. **3)** `GET /api/lab04/crash` – `500` s tekstom poput:

   ```text
   System.InvalidOperationException: Neuspjelo spajanje na bazu 'vulnshop-prod' (korisnik: sa, host: db.interno.local:1433)
      at VulnShop.Api.Labs.Lab04.Lab04Controller.Crash() in .../Lab04Controller.cs:line 22
      ...
   ```

   (u pregledniku je to cijela HTML stranica s karticama *Stack*, *Query*, *Headers*, *Environment* …).
4. **4)** CORS preflight s napadačkog origina:

   ```bash
   curl -s -i -X OPTIONS http://localhost:5080/api/lab04/ping \
     -H "Origin: https://evil.example" -H "Access-Control-Request-Method: GET"
   ```

   Odgovor sadrži `Access-Control-Allow-Origin: https://evil.example` i `Access-Control-Allow-Credentials: true`.
5. **OWASP ZAP:** *Automated Scan* na `http://localhost:5080/api/lab04/ping` i `/api/lab04/crash` →
   alarmi *X-Content-Type-Options Header Missing*, *Missing Anti-clickjacking Header*, *CSP Header Not Set*,
   *Application Error Disclosure*, *Cross-Domain Misconfiguration*.

## 5. Analiza uzroka

```csharp
.SetIsOriginAllowed(_ => true) ... .AllowCredentials()   // CORS: svaki origin + vjerodajnice
app.UseDeveloperExceptionPage();                          // bez provjere okruženja
public static WebApplication UseLab04SecurityHeaders(...) { return app; }   // ništa se ne postavlja
public IActionResult DebugConfig() => Ok(configuration.AsEnumerable()...)  // sve, uključujući tajne
```

Zajednički uzrok: postavke prikladne za razvoj (ili za "da samo proradi") prenesene su u produkciju, a
sigurnosne zadane vrijednosti nisu uključene. Napomena: ASP.NET Core **sam** uključuje developersku stranicu
grešaka samo u okruženju *Development* – ovdje je to pokvareno eksplicitnim pozivom.

## 6. Popravak

- **Debug/dijagnostički endpointi:** ukloniti ili ograničiti na `Development` (i tada maskirati tajne);
  u produkciji samo `/health` (bez detalja).
- **Greške:** `UseDeveloperExceptionPage()` samo kada je `app.Environment.IsDevelopment()`; inače
  `UseExceptionHandler` s generičkim **ProblemDetails** odgovorom i korelacijskim ID-om (detalji idu u log).
- **CORS:** allowlista originova iz konfiguracije (`WithOrigins(...)`), samo potrebne metode i zaglavlja;
  nikad `AllowAnyOrigin`/`SetIsOriginAllowed(_ => true)` zajedno s vjerodajnicama.
- **Zaglavlja:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'self'`, `Referrer-Policy: no-referrer` (u produkciji iza HTTPS-a i
  `Strict-Transport-Security` preko `app.UseHsts()`).
- Tajne nikad u `appsettings.json` u repozitoriju: *User Secrets* za razvoj, varijable okoline / Key Vault za produkciju.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab04/Lab04Setup.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration (CWE-16, CWE-209, CWE-942, CWE-693).
///
/// ISPRAVLJENO:
///  - CORS: samo originovi s popisa u konfiguraciji (<c>Lab04:AllowedOrigins</c>),
///  - detaljna stranica s greškom samo u okruženju Development; inače generički odgovor
///    (ProblemDetails) s korelacijskim ID-om, a detalji idu samo u log,
///  - sigurnosna zaglavlja na svakom odgovoru (nosniff, X-Frame-Options, CSP, Referrer-Policy).
/// </summary>
public static class Lab04Setup
{
    public static IServiceCollection AddLab04(this IServiceCollection services, IConfiguration configuration)
    {
        // ISPRAVLJENO: allowlista originova iz konfiguracije (appsettings.json → Lab04:AllowedOrigins).
        var allowedOrigins = configuration.GetSection("Lab04:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
        services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .WithOrigins(allowedOrigins)
            .WithMethods("GET", "POST", "PUT")
            .WithHeaders("Content-Type", "Authorization")));
        services.AddProblemDetails();
        return services;
    }

    public static WebApplication UseLab04ErrorHandling(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            // Detalji greške samo na razvojnom računalu.
            app.UseDeveloperExceptionPage();
        }
        else
        {
            // ISPRAVLJENO: generička poruka + korelacijski ID; detalji iznimke samo u logu.
            app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
            {
                var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
                var correlationId = context.TraceIdentifier;
                context.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("VulnShop.Api.Labs.Lab04.ErrorHandler")
                    .LogError(exception, "Neobrađena greška, correlationId={CorrelationId}", correlationId);

                var problem = new ProblemDetails
                {
                    Status = StatusCodes.Status500InternalServerError,
                    Title = "Došlo je do pogreške na poslužitelju.",
                    Detail = "Pokušajte ponovno ili se obratite podršci i navedite korelacijski ID.",
                };
                problem.Extensions["correlationId"] = correlationId;

                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
            }));
        }
        return app;
    }

    public static WebApplication UseLab04SecurityHeaders(this WebApplication app)
    {
        // ISPRAVLJENO: sigurnosna zaglavlja na SVAKOM odgovoru. Dodaju se neposredno prije slanja
        // odgovora (OnStarting), pa ih ima i odgovor koji je izradio rukovatelj greškama.
        // Ako je endpoint već postavio stroži CSP (npr. Lab08), on se ne prepisuje.
        app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                if (!headers.ContainsKey("Content-Security-Policy"))
                {
                    headers.ContentSecurityPolicy = "default-src 'self'";
                }
                return Task.CompletedTask;
            });
            await next();
        });
        return app;
    }
}
```


Datoteka `src/VulnShop.Api/Labs/Lab04/Lab04Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration.
///
/// ISPRAVLJENO: <c>GET /api/lab04/debug/config</c> postoji samo u okruženju Development
/// (inače 404), a i tada su vrijednosti osjetljivih ključeva (Key, Secret, Password …) maskirane.
/// </summary>
[ApiController]
[Route("api/lab04")]
public sealed class Lab04Controller(IConfiguration configuration, IWebHostEnvironment environment) : ControllerBase
{
    private static readonly string[] SensitiveMarkers = ["key", "secret", "password", "token", "connectionstring"];

    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { status = "ok" });

    [HttpGet("crash")]
    public IActionResult Crash() =>
        throw new InvalidOperationException(
            "Neuspjelo spajanje na bazu 'vulnshop-prod' (korisnik: sa, host: db.interno.local:1433)");

    /// <summary>ISPRAVLJENO: samo u Developmentu i s maskiranim tajnama.</summary>
    [HttpGet("debug/config")]
    public IActionResult DebugConfig()
    {
        if (!environment.IsDevelopment())
        {
            return NotFound();
        }

        return Ok(configuration.AsEnumerable()
            .Where(kv => kv.Value is not null)
            .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(kv => kv.Key, kv => IsSensitive(kv.Key) ? "***" : kv.Value));
    }

    private static bool IsSensitive(string key) =>
        SensitiveMarkers.Any(marker => key.Contains(marker, StringComparison.OrdinalIgnoreCase));
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab04"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab04"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab04]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab04` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab04*.
- **Rider:** *Unit Tests* → desni klik na `Lab04SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab04/Lab04SecurityTests.cs` i `Lab04FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Sigurnosni testovi pokreću aplikaciju s `UseEnvironment("Production")` i provjeravaju: debug endpoint →
404/401/403 bez tajne; `/crash` → 500 bez `VulnShop.Api`, `Exception`, redaka stack tracea i internog hosta;
preflight s `https://evil.example` → bez `Access-Control-Allow-Origin`; `ping` → `nosniff` i `DENY`.

### b) Ponovljeni napad

Pokrenite profil **http-production** i ponovite zahtjeve 1)–4): sigurnosna zaglavlja su prisutna,
`debug/config` vraća `404`, `crash` vraća

```json
{"title":"Došlo je do pogreške na poslužitelju.","status":500,"detail":"Pokušajte ponovno ili se obratite podršci i navedite korelacijski ID.","correlationId":"0HN..."}
```

a preflight s `https://evil.example` nema `Access-Control-Allow-Origin`. U profilu **http** (Development)
developerska stranica i debug endpoint (s maskiranim tajnama) i dalje rade – to je namjerno.

### c) Ponovno skeniranje

Ponovite ZAP skeniranje: alarmi za zaglavlja i *Application Error Disclosure* moraju nestati.
Dodatno: <https://securityheaders.com> analizira javne stranice – za lokalni rad koristite ZAP.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte zaglavlje `Permissions-Policy: camera=(), microphone=(), geolocation=()` i test koji
provjerava da ga ima odgovor na `/api/lab04/ping`. Zatim napišite test koji provjerava da preflight s
dopuštenog origina (`http://localhost:5080`) **dobiva** `Access-Control-Allow-Origin`.

**Pitanja za razmišljanje:**

1. Zašto je kombinacija "bilo koji origin" + `AllowCredentials` posebno opasna, a `AllowAnyOrigin()` bez vjerodajnica manje?
2. Koje informacije iz stack tracea napadač može iskoristiti u sljedećem koraku napada?
3. Kako biste u timu osigurali da se razvojne postavke ne prenesu u produkciju (konfiguracija po okruženju, CI provjere, IaC)?
