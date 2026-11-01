# Lab14 – Propusti u sigurnosnom logiranju i uzbunjivanju

> **OWASP Top 10:2025:** A09 Security Logging and Alerting Failures · **CWE:** CWE-778 (Insufficient
> Logging), CWE-117 (Improper Output Neutralization for Logs), CWE-532 (Insertion of Sensitive Information
> into Log File) · **Endpoint:** `POST /api/lab14/login` · **Zahtjevi:** `http/lab14.http`

## 1. Cilj vježbe

Prijava zapisuje **lozinku** u log, dopušta **krivotvorenje redaka loga** (CR/LF u korisničkom imenu), a
neuspjele prijave uopće **ne bilježi** – napad pogađanjem lozinke ostaje nevidljiv. Naučit ćete pisati
sigurnosne događaje i upozorenja i testirati sadržaj loga vlastitim `ILoggerProviderom`.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab14/Lab14Controller.cs`, metoda `Login` |
| Provjera lozinke | `src/VulnShop.Api/Common/UserService.cs` (tablica `users`: ana, marko, admin) |
| Hvatanje logova u testu | `tests/VulnShop.Tests/Infrastructure/InMemoryLoggerProvider.cs` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab14/Lab14SecurityTests.cs`, `Lab14FunctionalTests.cs` |

## 3. Opis ranjivosti

Logovi su istodobno **izvor dokaza** i **meta napada**:

- **CWE-532 – tajne u logu:** lozinke, tokeni, brojevi kartica u logovima čita mnogo više ljudi i sustava
  (podrška, SIEM, sigurnosne kopije, vanjski servisi) nego bazu. Korisnici često utipkaju lozinku u polje za
  korisničko ime – i ona završi u logu. (Twitter, 2018. i GitHub, 2018. – lozinke u internim logovima.)
- **CWE-117 – log injection:** znak novog retka u unosu omogućuje napadaču da u log upiše cijeli lažni zapis
  (npr. "uspješna prijava admina") i zbuni istragu ili alate za analizu. U HTML pregledniku logova to može
  postati i XSS.
- **CWE-778 – nedovoljno logiranje:** bez zapisa o neuspjelim prijavama i bez upozorenja na niz neuspjeha
  napad se ne može otkriti ni istražiti. Prosječno vrijeme otkrivanja proboja mjeri se mjesecima – često
  ga otkrije treća strana, a ne žrtva.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju u terminalu (`dotnet run --project src/VulnShop.Api --launch-profile http`) i
**promatrajte konzolu** dok šaljete zahtjeve iz `http/lab14.http`.

1. **1)** uspješna prijava ana → u konzoli:

   ```text
   info: VulnShop.Api.Labs.Lab14.Lab14Controller[0]
         Login attempt user=ana password=Ana123!
   ```

   **Lozinka je u logu.**
2. **2)** neuspjela prijava admina → opet lozinka u logu (`pogadjam1`), a o neuspjehu **nema** zapisa.
3. **3)** log injection – korisničko ime s `\n`:

   ```json
   {"username": "ana\n2026-11-02 10:00:00 INFO Login successful user=admin", "password": "x"}
   ```

   U konzoli (i u svakoj tekstualnoj log datoteci) pojavljuje se zaseban redak
   `2026-11-02 10:00:00 INFO Login successful user=admin` koji izgleda kao pravi zapis.
4. **4)** pošaljite pet neuspjelih prijava za `admin` – nikakvo upozorenje. Isto bi bilo i sa 100 000 pokušaja
   (npr. Burp Intruder s `wordlists/top-100.txt`, kao u Lab11).

## 5. Analiza uzroka

```csharp
logger.LogInformation("Login attempt user=" + username + " password=" + password);   // tajna + CR/LF + konkatenacija
...
if (user is null)
{
    // RANJIVO: neuspjeh se ne bilježi.
    return Unauthorized(...);
}
```

Poruka se gradi konkatenacijom (gubi se strukturirano logiranje), u nju ulaze tajna i neočišćen unos, a
sigurnosno relevantan događaj (neuspjeh) se preskače.

## 6. Popravak

- **Nikad ne logirati tajne** (lozinke, tokene, ključeve, puni broj kartice); po potrebi maskirati.
- **Neutralizirati CR/LF** i ostale kontrolne znakove u korisničkom unosu prije logiranja (zamjena s `_`),
  skratiti predug unos.
- **Strukturirano logiranje** s predloškom poruke (`"... user={User}"`) – vrijednosti se zasebno spremaju kao
  polja (u JSON logu su i dodatno kodirane).
- **Sigurnosni događaji** s dogovorenim, pretraživim oznakama:
  - `SECURITY_EVENT LOGIN_FAILED user=... ip=...` (Warning),
  - `SECURITY_EVENT LOGIN_SUCCESS user=... ip=...` (Information),
  - `SECURITY_ALERT BRUTE_FORCE_SUSPECTED user=... ip=... failures=...` (Error) nakon 5 neuspjeha za istog
    korisnika unutar 5 minuta.
- U produkciji: JSON logovi (`builder.Logging.AddJsonConsole()` ili Serilog), centralizacija u SIEM
  (Elastic, Splunk, Microsoft Sentinel), korelacijski ID, alarmi na `SECURITY_ALERT`, zaštita logova od
  izmjene i definirano razdoblje čuvanja (GDPR).

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab14/Lab14Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab14;

/// <summary>
/// Lab14 – A09 Security Logging and Alerting Failures (CWE-778, CWE-117, CWE-532).
///
/// ISPRAVLJENO:
///  - lozinka (i druge tajne) se NIKAD ne zapisuju u log,
///  - korisnički unos se prije logiranja neutralizira (CR/LF i ostali kontrolni znakovi → '_'),
///  - strukturirano logiranje s predloškom poruke (<c>{User}</c>), ne konkatenacijom,
///  - sigurnosni događaji: <c>SECURITY_EVENT LOGIN_FAILED</c> (Warning), <c>SECURITY_EVENT LOGIN_SUCCESS</c>
///    (Information) te <c>SECURITY_ALERT BRUTE_FORCE_SUSPECTED</c> (Error) nakon 5 neuspjeha za istog
///    korisnika unutar 5 minuta.
/// U produkciji: JSON logovi, centralizacija (SIEM), korelacijski ID, alarmi na SECURITY_ALERT.
/// </summary>
[ApiController]
[Route("api/lab14")]
public sealed class Lab14Controller(UserService users, IMemoryCache cache, ILogger<Lab14Controller> logger) : ControllerBase
{
    private const int AlertThreshold = 5;
    private static readonly TimeSpan AlertWindow = TimeSpan.FromMinutes(5);
    private static readonly object Sync = new();

    public sealed record LoginRequest(string? Username, string? Password);

    private sealed class FailureWindow
    {
        public int Count { get; set; }
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var safeUser = Sanitize(username);
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "nepoznata";

        // ISPRAVLJENO: bez lozinke, s neutraliziranim korisničkim imenom.
        logger.LogInformation("Login attempt user={User}", safeUser);

        var user = users.VerifyCredentials(username, request.Password);
        if (user is null)
        {
            // ISPRAVLJENO: neuspjeh je sigurnosni događaj.
            logger.LogWarning("SECURITY_EVENT LOGIN_FAILED user={User} ip={Ip}", safeUser, ip);

            var failures = RegisterFailure(username);
            if (failures >= AlertThreshold)
            {
                logger.LogError(
                    "SECURITY_ALERT BRUTE_FORCE_SUSPECTED user={User} ip={Ip} failures={Failures} window={WindowMinutes}min",
                    safeUser, ip, failures, AlertWindow.TotalMinutes);
            }
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        logger.LogInformation("SECURITY_EVENT LOGIN_SUCCESS user={User} ip={Ip}", safeUser, ip);
        return Ok(new { status = "prijavljen", username = user.Username });
    }

    /// <summary>Neutralizira CR, LF i ostale kontrolne znakove (CWE-117) i skraćuje predug unos.</summary>
    public static string Sanitize(string value)
    {
        var chars = value.Select(c => char.IsControl(c) ? '_' : c).ToArray();
        var cleaned = new string(chars);
        return cleaned.Length > 100 ? cleaned[..100] + "…" : cleaned;
    }

    private int RegisterFailure(string username)
    {
        lock (Sync)
        {
            // Prozor od 5 minuta počinje prvim neuspjehom (apsolutni istek zapisa u cacheu).
            var window = cache.GetOrCreate("lab14:failures:" + username.ToLowerInvariant(), entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = AlertWindow;
                return new FailureWindow();
            })!;
            window.Count++;
            return window.Count;
        }
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab14"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab14"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab14]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab14` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab14*.
- **Rider:** *Unit Tests* → desni klik na `Lab14SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab14/Lab14SecurityTests.cs` i `Lab14FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Svaki test pokreće aplikaciju s vlastitim `InMemoryLoggerProvider`
(`factory.WithWebHostBuilder(b => b.ConfigureLogging(l => l.AddProvider(logs)))`) i provjerava zapise:
lozinka se ne pojavljuje; nijedan redak ne počinje krivotvorenim tekstom; neuspjela prijava daje zapis sa
`SECURITY_EVENT` i `LOGIN_FAILED`; nakon 5 neuspjeha postoji `SECURITY_ALERT`.

### b) Ponovljeni napad

Ponovite zahtjeve 1)–4) i promatrajte konzolu:

```text
info: VulnShop.Api.Labs.Lab14.Lab14Controller[0]
      Login attempt user=ana_2026-11-02 10:00:00 INFO Login successful user=admin
warn: VulnShop.Api.Labs.Lab14.Lab14Controller[0]
      SECURITY_EVENT LOGIN_FAILED user=ana_2026-11-02 10:00:00 INFO Login successful user=admin ip=::1
...
fail: VulnShop.Api.Labs.Lab14.Lab14Controller[0]
      SECURITY_ALERT BRUTE_FORCE_SUSPECTED user=admin ip=::1 failures=5 window=5min
```

Nijedna lozinka se ne pojavljuje u logu.

### c) Ponovno skeniranje

Pretražite izlaz aplikacije: `dotnet run ... | findstr /i password` (Windows) ili `| grep -i password` – nema
pogodaka s vrijednostima lozinki. SonarQube for IDE / Semgrep upozoravaju na logiranje neočišćenog unosa
(S5145 *log injection*).

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** uključite JSON logiranje u konzolu (`builder.Logging.AddJsonConsole()` u `Program.cs`) i
usporedite kako izgleda log injection pokušaj u JSON formatu. Napišite test koji provjerava da se nakon
uspješne prijave bilježi `SECURITY_EVENT LOGIN_SUCCESS`.

**Pitanja za razmišljanje:**

1. Koje sigurnosne događaje (osim prijave) bi web trgovina trebala bilježiti? Navedite barem pet.
2. Kako spriječiti da napadač zatrpa log (DoS na log/SIEM) i tako sakrije stvarni napad?
3. Koliko dugo čuvati logove s IP adresama i korisničkim imenima s obzirom na GDPR?
