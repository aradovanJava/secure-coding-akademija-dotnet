# Secure Coding akademija – VulnShop Akademija (C# / .NET 10)

Repozitorij s laboratorijskim vježbama za **Tjedan 1** mikrokvalifikacije
*Implementacija sigurnosnih mehanizama u programskoj podršci* (Span Centar kibernetičke sigurnosti, Zagreb).

**VulnShop Akademija** je namjerno ranjiva web trgovina (ASP.NET Core Web API) s 15 vježbi prema
**OWASP Top 10:2025**. U svakoj vježbi pronalazite ranjivost, iskorištavate je na vlastitom računalu,
analizirate uzrok, ispravljate kod i **jediničnim (integracijskim) testom dokazujete** da je ranjivost
otklonjena – po uzoru na OWASP WebGoat i Juice Shop.

> **UPOZORENJE – NAMJERNO RANJIVA APLIKACIJA**
>
> Aplikacija sadrži ozbiljne sigurnosne propuste (SQL injection, izvršavanje naredbi operacijskog sustava,
> SSRF, nesigurnu deserijalizaciju …). Pokrećite je **isključivo lokalno** (`http://localhost:5080`),
> nikad na javno dostupnom poslužitelju ili u produkcijskoj mreži. Napade izvodite **samo na vlastitu
> lokalnu instancu**. Kod iz grane `main` nikad ne kopirajte u stvarne projekte.

Java/Spring Boot inačica istih vježbi (isti endpointi, isti podaci, isto ponašanje):
<https://github.com/aradovanJava/secure-coding-akademija-java>

## Preduvjeti

| Alat | Verzija | Napomena |
|---|---|---|
| .NET SDK | 10.0.100 ili noviji 10.0.x | `dotnet --version` (vidi `global.json`) |
| Git | bilo koja novija | `git --version` |
| IDE (jedan od) | Visual Studio 2026, VS Code + C# Dev Kit, JetBrains Rider | detaljno u [docs/00-postavljanje-okruzenja.md](docs/00-postavljanje-okruzenja.md) |
| HTTP klijent | `.http` datoteke (VS / VS Code REST Client / Rider), curl, Burp Suite ili OWASP ZAP | vidi [docs/01-alati.md](docs/01-alati.md) |

## Brzi početak

```bash
git clone https://github.com/aradovanJava/secure-coding-akademija-dotnet.git
cd secure-coding-akademija-dotnet

# 1) build
dotnet build

# 2) pokretanje aplikacije na http://localhost:5080
dotnet run --project src/VulnShop.Api --launch-profile http

# 3) u drugom terminalu – provjera da je aplikacija pokrenuta
curl http://localhost:5080/health

# 4) testovi (aplikacija za testove NE mora biti pokrenuta – testovi je pokreću sami, u memoriji)
dotnet test --filter "Category=Functional"   # moraju proći
dotnet test --filter "Category=Security"     # na grani main PADAJU – to je dokaz ranjivosti
dotnet test --filter "Lab=Lab01"             # svi testovi jedne vježbe
```

> U PowerShellu koristite `curl.exe` (ne `curl`, koji je alias za `Invoke-WebRequest`) ili `Invoke-RestMethod`.

Seed korisnici zajedničke prijave (`POST /api/auth/login`):

| Korisnik | Lozinka | Uloga |
|---|---|---|
| `ana` | `Ana123!` | USER |
| `marko` | `Marko123!` | USER |
| `admin` | `Admin123!` | ADMIN |

Prijava vraća `{"token": "...", "username": "...", "role": "..."}`; token se šalje u zaglavlju
`Authorization: Bearer <token>`. U `.http` datotekama token ručno kopirate u varijablu `@token`.

## Vježbe

| Lab | OWASP Top 10:2025 | CWE | Endpoint(i) | Uputa |
|---|---|---|---|---|
| Lab01 | A01 Broken Access Control – IDOR | CWE-639 | `GET /api/lab01/orders/{id}` | [lab01-idor.md](docs/labs/lab01-idor.md) |
| Lab02 | A01 Broken Access Control – mass assignment | CWE-915, CWE-269 | `GET/PUT /api/lab02/profile`, `GET /api/lab02/admin/users` | [lab02-mass-assignment.md](docs/labs/lab02-mass-assignment.md) |
| Lab03 | A01 Broken Access Control – SSRF | CWE-918 | `GET /api/lab03/preview?url=` | [lab03-ssrf.md](docs/labs/lab03-ssrf.md) |
| Lab04 | A02 Security Misconfiguration | CWE-16, CWE-209, CWE-942, CWE-693 | `GET /api/lab04/ping`, `/crash`, `/debug/config` | [lab04-misconfiguration.md](docs/labs/lab04-misconfiguration.md) |
| Lab05 | A03 Software Supply Chain Failures | CWE-1104, CWE-1395 | `POST /api/lab05/import` | [lab05-supply-chain.md](docs/labs/lab05-supply-chain.md) |
| Lab06 | A04 Cryptographic Failures | CWE-916, CWE-327, CWE-321, CWE-329 | `/api/lab06/register`, `/login`, `/customers/export`, `/cards` | [lab06-crypto.md](docs/labs/lab06-crypto.md) |
| Lab07 | A05 Injection – SQL injection | CWE-89 | `GET /api/lab07/products/search?q=`, `POST /api/lab07/login` | [lab07-sql-injection.md](docs/labs/lab07-sql-injection.md) |
| Lab08 | A05 Injection – XSS | CWE-79 | `GET /lab08/search?q=`, `POST /api/lab08/reviews`, `GET /lab08/products/{id}/reviews` | [lab08-xss.md](docs/labs/lab08-xss.md) |
| Lab09 | A05 Injection – OS command injection | CWE-78 | `GET /api/lab09/ping?host=` | [lab09-command-injection.md](docs/labs/lab09-command-injection.md) |
| Lab10 | A06 Insecure Design – poslovna logika | CWE-840, CWE-20 | `GET /api/lab10/wallet`, `POST /api/lab10/checkout` | [lab10-business-logic.md](docs/labs/lab10-business-logic.md) |
| Lab11 | A07 Authentication Failures – brute force, enumeracija | CWE-307, CWE-204 | `POST /api/lab11/login` | [lab11-brute-force.md](docs/labs/lab11-brute-force.md) |
| Lab12 | A07 Authentication Failures – JWT | CWE-347, CWE-798, CWE-613 | `POST /api/lab12/login`, `GET /api/lab12/me`, `/admin` | [lab12-jwt.md](docs/labs/lab12-jwt.md) |
| Lab13 | A08 Software or Data Integrity Failures – deserijalizacija | CWE-502 | `POST /api/lab13/cart/import` | [lab13-deserialization.md](docs/labs/lab13-deserialization.md) |
| Lab14 | A09 Security Logging & Alerting Failures | CWE-778, CWE-117, CWE-532 | `POST /api/lab14/login` | [lab14-logging.md](docs/labs/lab14-logging.md) |
| Lab15 | A10 Mishandling of Exceptional Conditions | CWE-636, CWE-755, CWE-209, CWE-460 | `GET /api/lab15/accounts`, `POST /api/lab15/transfer` | [lab15-exceptions.md](docs/labs/lab15-exceptions.md) |

Za svaku vježbu postoji `http/labXX.http` s gotovim zahtjevima za napad i provjeru popravka.

## Način rada: crveno → zeleno

Svaka vježba ima dvije vrste testova:

- **sigurnosni testovi** (`LabXXSecurityTests`, `[Trait("Category", "Security")]`) – opisuju *sigurno*
  ponašanje. Na grani `main` **padaju** (crveno) jer je kod ranjiv; nakon ispravnog popravka **prolaze** (zeleno).
- **funkcionalni testovi** (`LabXXFunctionalTests`, `[Trait("Category", "Functional")]`) – opisuju
  normalno ponašanje aplikacije i prolaze **uvijek** – popravak ne smije pokvariti funkcionalnost.

Tijek rada za svaku vježbu:

1. pročitajte uputu `docs/labs/labXX-*.md` i pokrenite sigurnosne testove vježbe – padaju:
   `dotnet test --filter "Category=Security&Lab=Lab01"`
2. pokrenite aplikaciju i izvedite napad (`http/labXX.http`, curl, Burp Suite ili OWASP ZAP),
3. pronađite uzrok u kodu (`src/VulnShop.Api/Labs/LabXX/`), ispravite ga,
4. ponovno pokrenite testove vježbe – sigurnosni i funkcionalni moraju proći: `dotnet test --filter "Lab=Lab01"`,
5. ponovite napad i potvrdite da više ne uspijeva,
6. riješite zadatak za samostalni rad (npr. dodatni test) s kraja upute.

Vježbe su međusobno neovisne (vlastiti namespace i tablice `labXX_*`) pa ih možete rješavati bilo kojim redoslijedom.

## Grane

| Grana | Sadržaj |
|---|---|
| `main` | ranjiva aplikacija + sigurnosni testovi (padaju) + funkcionalni testovi (prolaze) + sve upute |
| `rjesenja` | `main` + ispravci svih 15 ranjivosti; **svi testovi prolaze** |

Upute već sadrže referentno rješenje (sklopivi blok *Referentno rješenje*), a cjeloviti kod je u grani
`rjesenja`. Usporedba vaše verzije s rješenjem:

```bash
git fetch origin
git diff main origin/rjesenja -- src/VulnShop.Api/Labs/Lab01
```

GitHub Actions (`.github/workflows/ci.yml`) na svakom pushu gradi rješenje, pokreće testove i ispisuje
sažetak po vježbi (npr. `Lab01: RANJIVO (2/2 testova pada)` na `main`, `Lab01: ISPRAVLJENO (2/2 prolazi)` na `rjesenja`).

## Struktura repozitorija

```text
secure-coding-akademija-dotnet/
├── SecureCodingAkademija.sln          # rješenje (VS 2026, VS Code C# Dev Kit, Rider)
├── global.json                         # .NET SDK 10.0.100 (rollForward: latestFeature)
├── src/VulnShop.Api/                   # ASP.NET Core Web API (controllers)
│   ├── Program.cs                      # konfiguracija aplikacije
│   ├── Common/                         # zajednička infrastruktura: baza, prijava (NIJE dio vježbi)
│   ├── Labs/Lab01 … Lab15/             # kod vježbi (namespace VulnShop.Api.Labs.LabXX)
│   ├── Properties/launchSettings.json  # profili "http" i "http-production" (port 5080)
│   └── appsettings.json
├── tests/VulnShop.Tests/               # xUnit + WebApplicationFactory<Program>
│   ├── Infrastructure/                 # tvornica aplikacije, pomoćne metode, hvatanje logova
│   └── Labs/Lab01 … Lab15/             # LabXXSecurityTests, LabXXFunctionalTests
├── http/lab01.http … lab15.http        # gotovi HTTP zahtjevi (napad + provjera)
├── docs/
│   ├── 00-postavljanje-okruzenja.md    # instalacija i rad u IDE-u
│   ├── 01-alati.md                     # ZAP, Burp, Semgrep, SCA alati …
│   └── labs/lab01-*.md … lab15-*.md    # upute za vježbe
├── wordlists/top-100.txt               # 100 najčešćih lozinki (Lab06, Lab11, Lab12)
└── .github/workflows/ci.yml            # CI: build + funkcionalni + sigurnosni testovi + sažetak
```

Tehnologije: .NET 10 (LTS), ASP.NET Core (controllers), SQLite in-memory preko `Microsoft.Data.Sqlite`
(sirovi ADO.NET, bez EF Core), xUnit, `Microsoft.AspNetCore.Mvc.Testing`. Paket `Newtonsoft.Json 12.0.3`
je **namjerno zastario** (Lab05) – NuGet će pri buildu ispisati upozorenje NU1903, što je očekivano.

Baza je u memoriji: svako pokretanje aplikacije (i svaki test) kreće od istih početnih podataka.
Ako se tijekom vježbe "pokvare" podaci, samo ponovno pokrenite aplikaciju.

## Licenca i namjena

Materijal je namijenjen isključivo edukaciji o sigurnom programiranju. Tehnike napada smiju se
primjenjivati samo na vlastitim sustavima ili uz izričito pisano dopuštenje vlasnika sustava.
