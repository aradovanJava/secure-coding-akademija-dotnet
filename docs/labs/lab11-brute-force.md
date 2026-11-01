# Lab11 – Pogađanje lozinki (brute force) i enumeracija korisnika

> **OWASP Top 10:2025:** A07 Authentication Failures · **CWE:** CWE-307 (Improper Restriction of Excessive
> Authentication Attempts), CWE-204 (Observable Response Discrepancy) · **Endpoint:** `POST /api/lab11/login` ·
> **Zahtjevi:** `http/lab11.http`

## 1. Cilj vježbe

Prijava otkriva postoji li korisničko ime (različite poruke) i ne ograničava broj pokušaja. Profesionalnim
alatom (Burp Suite Intruder ili OWASP ZAP Fuzzer) prvo ćete utvrditi postojeće račune, a zatim rječnikom
pogoditi slabu lozinku. Popravak: jedinstveni odgovor, ujednačeno vrijeme i zaključavanje nakon 5 neuspjeha.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab11/Lab11Controller.cs`, metoda `Login` |
| Podaci | `lab11_users`: `ivana` / `sunshine1` (nalazi se u `wordlists/top-100.txt`), `tomislav` / `T0m!slav#2026`, `lockme` / `Lock!Me2026` (za test zaključavanja) – seed u `DbInitializer.SeedLab11` |
| Rječnik | `wordlists/top-100.txt` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab11/Lab11SecurityTests.cs`, `Lab11FunctionalTests.cs` |

## 3. Opis ranjivosti

- **Enumeracija (CWE-204):** `404 "Korisnik ne postoji."` naspram `401 "Pogrešna lozinka."` – napadač
  provjerava popis imena/e-adresa i dobiva točan popis računa. Enumeracija se može dogoditi i preko razlike u
  **vremenu** odgovora (hash lozinke računa se samo za postojeće korisnike), duljini odgovora ili poruci
  funkcije "zaboravljena lozinka".
- **Brute force / password spraying / credential stuffing (CWE-307):** bez ograničenja pokušaja napadač
  isprobava rječnik lozinki (ili lozinke procurjele s drugih servisa) dok ne pogodi.

Primjeri: *credential stuffing* napadi na Disney+, Spotify, 23andMe (2023. – 14 000 računa preuzeto
procurjelim lozinkama, a zatim podaci 6,9 milijuna korisnika).

## 4. Eksploatacija – korak po korak

> Napad se izvodi **profesionalnim alatima** (Burp Suite Intruder ili OWASP ZAP Fuzzer) nad vlastitom
> lokalnom instancom. Ovaj repozitorij namjerno ne sadrži skripte za brute force.

### 4.1 Ručna provjera (`http/lab11.http`)

1. **1)** nepostojeći korisnik → `404 {"error":"Korisnik ne postoji."}`
2. **2)** `ivana` s krivom lozinkom → `401 {"error":"Pogrešna lozinka."}` → **ivana postoji**.
3. **3)** nekoliko ručnih pokušaja čestih lozinaka – svi `401`, nikakvog ograničenja.

### 4.2 Enumeracija – Burp Intruder

1. Pošaljite zahtjev 1) kroz Burp (Burpov preglednik ili proxy `127.0.0.1:8080`), u *HTTP history* desni
   klik → **Send to Intruder**.
2. *Positions*: **Clear §**, označite vrijednost `username` → **Add §**. Vrsta napada *Sniper*.
3. *Payloads*: *Simple list* – upišite `ana`, `ivana`, `tomislav`, `petar`, `admin`, `lockme`, `marija`.
4. **Start attack** i sortirajte po stupcu *Status*: `401` = postoji, `404` = ne postoji.

### 4.3 Brute force – Burp Intruder (ili ZAP Fuzzer)

1. Novi Intruder napad na `{"username":"ivana","password":"§x§"}`.
2. *Payloads* → *Simple list* → **Load…** → `wordlists/top-100.txt` → **Start attack**.
3. Redak sa statusom **200** (i drukčijom duljinom odgovora) otkriva lozinku `sunshine1`.

**OWASP ZAP:** zahtjev u *History* → desni klik → *Attack → Fuzz…* → označite vrijednost lozinke →
*Payloads → Add → Type: File* → `wordlists/top-100.txt` → *Start Fuzzer*; sortirajte po stupcu *Code*.

## 5. Analiza uzroka

```csharp
if (storedHash is null)
    return NotFound(new { error = "Korisnik ne postoji." });          // otkriva postojanje računa
if (Hasher.VerifyHashedPassword(...) == PasswordVerificationResult.Failed)
    return Unauthorized(new { error = "Pogrešna lozinka." });         // drukčiji odgovor
// nigdje se ne broje neuspjeli pokušaji
```

Dodatno: za nepostojećeg korisnika hash se ne računa pa je odgovor **brži** – vremenska enumeracija.

## 6. Popravak

- Jedinstven odgovor za oba slučaja: `401 "Neispravno korisničko ime ili lozinka."` (isti status, isto tijelo).
- Provjera lozinke i za nepostojećeg korisnika (lažni hash) – ujednačeno vrijeme odgovora.
- **Zaključavanje** nakon 5 neuspjelih pokušaja na 15 minuta → `429 Too Many Requests`. Brojač se vodi po
  korisničkom imenu – i za nepostojeća imena, kako ni zaključavanje ne bi otkrilo postoji li račun.
- U produkciji dodatno: **MFA**, CAPTCHA nakon nekoliko neuspjeha, *rate limiting* po IP adresi
  (`Microsoft.AspNetCore.RateLimiting`), provjera lozinki protiv procurjelih (Have I Been Pwned *k-anonymity* API),
  obavijest korisniku o sumnjivim prijavama. Pazite da zaključavanje ne postane DoS alat protiv legitimnih korisnika
  (vremensko, a ne trajno zaključavanje; progresivna odgoda).

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab11/Lab11Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab11;

/// <summary>
/// Lab11 – A07 Authentication Failures: brute force i enumeracija korisnika (CWE-307, CWE-204).
///
/// ISPRAVLJENO:
///  - jedinstven odgovor 401 "Neispravno korisničko ime ili lozinka." za nepostojećeg korisnika
///    i za krivu lozinku,
///  - lozinka se provjerava i za nepostojećeg korisnika (lažni hash) – ujednačeno vrijeme odgovora,
///  - nakon 5 neuspjelih pokušaja korisničko ime se zaključava na 15 minuta → 429 Too Many Requests
///    (brojač se vodi za svako korisničko ime, i za nepostojeće, pa ni zaključavanje ne otkriva
///    postoji li račun).
/// U produkciji dodatno: MFA, CAPTCHA nakon nekoliko pokušaja, rate limiting po IP adresi
/// (<c>Microsoft.AspNetCore.RateLimiting</c>), obavijest korisniku o sumnjivim prijavama.
/// </summary>
[ApiController]
[Route("api/lab11")]
public sealed class Lab11Controller(Db db, IMemoryCache cache) : ControllerBase
{
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly PasswordHasher<string> Hasher = new();
    private static readonly string DummyHash = Hasher.HashPassword(string.Empty, "lazna-lozinka-za-ujednaceno-vrijeme");
    private static readonly object Sync = new();

    public sealed record LoginRequest(string? Username, string? Password);

    private sealed class AttemptState
    {
        public int Failures { get; set; }
        public DateTimeOffset? LockedUntil { get; set; }
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var username = request.Username ?? string.Empty;
        var password = request.Password ?? string.Empty;
        var state = GetState(username);

        // ISPRAVLJENO: zaključan račun → 429 (i prije provjere lozinke).
        lock (Sync)
        {
            if (state.LockedUntil is { } until && until > DateTimeOffset.UtcNow)
            {
                return StatusCode(StatusCodes.Status429TooManyRequests,
                    new { error = "Previše neuspjelih pokušaja. Pokušajte ponovno za 15 minuta." });
            }
        }

        var storedHash = db.Scalar(
            "SELECT password_hash FROM lab11_users WHERE username = $u", ("$u", username)) as string;

        // ISPRAVLJENO: hash se provjerava UVIJEK (lažni hash za nepostojećeg korisnika) – isto vrijeme.
        var passwordOk = Hasher.VerifyHashedPassword(username, storedHash ?? DummyHash, password)
                         != PasswordVerificationResult.Failed;

        if (storedHash is null || !passwordOk)
        {
            lock (Sync)
            {
                state.Failures++;
                if (state.Failures >= MaxFailedAttempts)
                {
                    state.LockedUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
                    state.Failures = 0;
                }
            }
            // ISPRAVLJENO: jedinstven odgovor – ne otkriva postoji li korisnik.
            return Unauthorized(new { error = "Neispravno korisničko ime ili lozinka." });
        }

        lock (Sync)
        {
            state.Failures = 0;
        }
        return Ok(new { status = "prijavljen", username });
    }

    private AttemptState GetState(string username) =>
        cache.GetOrCreate("lab11:attempts:" + username.ToLowerInvariant(), entry =>
        {
            entry.SlidingExpiration = TimeSpan.FromHours(1);
            return new AttemptState();
        })!;
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab11"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab11"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab11]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab11` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab11*.
- **Rider:** *Unit Tests* → desni klik na `Lab11SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab11/Lab11SecurityTests.cs` i `Lab11FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi: nepostojeći korisnik i kriva lozinka za `tomislav` → isti status i isto tijelo; 5 krivih lozinki za
`lockme`, zatim ispravna → `429`. (Zaseban korisnik `lockme` osigurava da zaključavanje ne utječe na druge testove.)

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju: zahtjevi 1) i 2) vraćaju identičan `401`. Ponovite Intruder napad iz 4.3:
nakon pet `401` odgovora svi daljnji su `429` – i za `sunshine1`. Prijava `ivana` / `sunshine1` na
svježe pokrenutoj aplikaciji radi (`200`).

### c) Ponovno skeniranje

Intruder enumeracija iz 4.2 više ne razlikuje postojeće i nepostojeće korisnike (isti status i duljina).
Za vremensku analizu u Intruderu uključite stupce *Response received* / *Response completed*.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte globalni *rate limiter* (`builder.Services.AddRateLimiter(...)` s
`FixedWindowLimiter`, npr. 20 zahtjeva u minuti po IP adresi) na endpoint `/api/lab11/login`
(`[EnableRateLimiting("login")]`) i napišite test koji šalje 25 zahtjeva i očekuje barem jedan `429`.

**Pitanja za razmišljanje:**

1. Kako *password spraying* (jedna česta lozinka na mnogo računa) zaobilazi zaključavanje po računu? Kako se braniti?
2. Zašto i zaključavanje računa može otkriti postoji li korisnik, i kako je to riješeno u referentnom rješenju?
3. Koje su prednosti i nedostaci MFA-a putem SMS-a, TOTP aplikacije i ključeva FIDO2/passkeys?
