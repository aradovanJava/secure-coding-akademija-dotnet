# Lab05 – Ranjiva ovisnost (lanac opskrbe softvera)

> **OWASP Top 10:2025:** A03 Software Supply Chain Failures · **CWE:** CWE-1104 (Use of Unmaintained Third
> Party Components), CWE-1395 (Dependency on Vulnerable Third-Party Component) ·
> **Endpoint:** `POST /api/lab05/import` · **Zahtjevi:** `http/lab05.http`

## 1. Cilj vježbe

Aplikacija koristi zastarjeli paket **Newtonsoft.Json 12.0.3** s javno poznatom ranjivošću
(GHSA-5crp-9r3c-p9vr): duboko ugniježđen JSON ruši cijeli proces (*Denial of Service*). Naučit ćete
alatima pronaći ranjivu ovisnost, nadograditi je, dodati obrambene postavke (ograničenje dubine i
veličine) i testom potvrditi popravak.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Verzija paketa | `src/VulnShop.Api/VulnShop.Api.csproj` – `<PackageReference Include="Newtonsoft.Json" Version="12.0.3" />` |
| Endpoint | `src/VulnShop.Api/Labs/Lab05/Lab05ImportController.cs`, metoda `Import` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab05/Lab05SecurityTests.cs`, `Lab05FunctionalTests.cs` |

Isti paket koristi i Lab13 (`TypeNameHandling`) – nadogradnja ne mijenja ponašanje Lab13.

## 3. Opis ranjivosti

Velik dio koda svake aplikacije nije naš – dolazi iz paketa (NuGet, Maven, npm). Ranjivost u ovisnosti
je ranjivost aplikacije, čak i ako vlastiti kod nema greške. OWASP Top 10:2025 kategoriju A03 proširuje
s "ranjivih komponenti" na cijeli **lanac opskrbe**: ovisnosti, alate za build, CI/CD, registre paketa.

**GHSA-5crp-9r3c-p9vr** (Newtonsoft.Json < 13.0.1, ocjena *High*): `JsonConvert.DeserializeObject` nema
ograničenje dubine ugniježđivanja. JSON s desecima tisuća razina (`[[[[...`) iscrpi stog (*stack*) i baci
`StackOverflowException` – iznimka koju se u .NET-u **ne može uhvatiti**: proces se ruši, a s njim i sve
istodobne korisničke sesije. Napad je jeftin (stotinjak kB podataka). Verzija 13.0.1 uvodi zadani `MaxDepth = 64`.

Poznati primjeri štete iz lanca opskrbe: Log4Shell (Log4j, 2021.), Text4Shell (Apache Commons Text, 2022. –
vidi Java inačicu ove vježbe), Equifax 2017. (neažuriran Apache Struts → 147 milijuna zapisa), zlonamjerni
paketi u registrima (*typosquatting*) i kompromitirani alati (SolarWinds, xz-utils 2024.).

## 4. Eksploatacija – korak po korak

### 4.1 Pronalaženje ranjive ovisnosti alatima

```bash
dotnet list package --vulnerable --include-transitive
```

Očekivano:

```text
Project `VulnShop.Api` has the following vulnerable packages
   [net10.0]:
   Top-level Package      Requested   Resolved   Severity   Advisory URL
   > Newtonsoft.Json      12.0.3      12.0.3     High       https://github.com/advisories/GHSA-5crp-9r3c-p9vr
```

Isto javlja i svaki `dotnet build`/`restore` (NuGetAudit): `warning NU1903: Package 'Newtonsoft.Json' 12.0.3
has a known high severity vulnerability`. Ostali alati (vidi `docs/01-alati.md`, odjeljak 6):
`osv-scanner scan source -r .`, `trivy fs .`, OWASP Dependency-Check, GitHub Dependabot, SBOM pomoću CycloneDX
(`dotnet tool install --global CycloneDX`).

### 4.2 Izazivanje greške (sigurno)

Pokrenite aplikaciju i iz `http/lab05.http` pošaljite:

1. **1)** legitiman JSON → `200` `{"type":"Object","elements":6,"depth":4}`.
2. **2)** neispravan JSON → `500` s developerskom stranicom greške (neobrađen `JsonReaderException`).
3. **3)** JSON dubine 200 → s verzijom 12.0.3 parsiranje *uspije* jer nema ograničenja dubine:
   `200` s `"depth":200` – aplikacija prihvaća proizvoljno duboke strukture bez ikakve kontrole.

### 4.3 DoS – rušenje procesa (OPREZ)

> Ovaj korak **ruši aplikaciju**. Izvodite ga samo nad vlastitom lokalnom instancom.

```powershell
# PowerShell
$p = '[' * 100000
curl.exe -s -X POST http://localhost:5080/api/lab05/import -H "Content-Type: application/json" --data-raw $p
```

```bash
# bash
python3 -c "print('['*100000)" | curl -s -X POST http://localhost:5080/api/lab05/import \
  -H "Content-Type: application/json" --data-binary @-
```

**Očekivani rezultat:** curl javlja prekinutu vezu (`Empty reply from server`), a u konzoli aplikacije
`Stack overflow.` i proces završava. Svi ostali korisnici su ostali bez usluge.

> **Zašto se pad ne vidi u testovima?** `Microsoft.NET.Test.Sdk` u testni proces povlači Newtonsoft.Json
> **13.x**, pa unutar testova radi novija verzija i ranjivo ponašanje 12.0.3 nije moguće reproducirati.
> Sigurnosni testovi zato provjeravaju (a) s kojom je verzijom API projekt **kompajliran** i (b) da JSON
> dubine 200 vraća kontrolirani `400` (ranjivi kod nema `try/catch`, pa vraća `500` – test pada).
> Pad procesa vidi se samo kad aplikaciju pokrenete samostalno (`dotnet run`) s verzijom 12.0.3.

## 5. Analiza uzroka

```xml
<PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
```

```csharp
var body = await reader.ReadToEndAsync();                 // tijelo bez ograničenja veličine
var token = JsonConvert.DeserializeObject<JToken>(body);  // zadane postavke ranjive verzije, bez MaxDepth, bez try/catch
```

Tri propusta: (1) zastarjela ovisnost s poznatim CVE/GHSA zapisom (nitko nije pratio upozorenja NU1903),
(2) oslanjanje na zadane postavke biblioteke umjesto eksplicitnih ograničenja, (3) neobrađena greška
parsiranja – neispravan ulaz klijenta postaje `500` umjesto `400`.

## 6. Popravak

1. **Nadogradite paket** na 13.0.3 (ili noviju 13.x):
   `dotnet add src/VulnShop.Api package Newtonsoft.Json --version 13.0.3`
   (Visual Studio: desni klik na projekt → *Manage NuGet Packages…* → *Updates*).
2. **Eksplicitno ograničenje dubine** (`MaxDepth = 32`) – obrana ne smije ovisiti o zadanoj vrijednosti verzije.
3. **Ograničenje veličine tijela** (`[RequestSizeLimit]`).
4. **`JsonReaderException` → 400** s generičkom porukom.
5. Proces: NuGetAudit upozorenja tretirati kao greške u CI-ju, Dependabot/Renovate za automatske PR-ove,
   `packages.lock.json` (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`) i
   `dotnet restore --locked-mode`, `packageSourceMapping` u `nuget.config`, SBOM uz svako izdanje.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/VulnShop.Api.csproj` (grana `rjesenja`):

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>VulnShop.Api</RootNamespace>
    <AssemblyName>VulnShop.Api</AssemblyName>
    <!-- NuGetAudit: upozorenja o ranjivim paketima (NU1901–NU1904) moraju ostati UPOZORENJA,
         jer je ranjivi Newtonsoft.Json 12.0.3 namjerno dio vježbe Lab05. -->
    <NuGetAudit>true</NuGetAudit>
    <NuGetAuditMode>all</NuGetAuditMode>
    <WarningsNotAsErrors>NU1901;NU1902;NU1903;NU1904</WarningsNotAsErrors>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Data.Sqlite" Version="10.0.0" />
    <!-- ISPRAVLJENO (Lab05): nadogradnja s ranjive 12.0.3 (GHSA-5crp-9r3c-p9vr) na 13.0.3. -->
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>

</Project>
```


Datoteka `src/VulnShop.Api/Labs/Lab05/Lab05ImportController.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace VulnShop.Api.Labs.Lab05;

/// <summary>
/// Lab05 – A03 Software Supply Chain Failures (CWE-1104, CWE-1395).
///
/// ISPRAVLJENO:
///  - paket nadograđen na <c>Newtonsoft.Json 13.0.3</c> (VulnShop.Api.csproj),
///  - eksplicitno ograničenje dubine (<c>MaxDepth = 32</c>) – ne oslanjamo se na zadane vrijednosti,
///  - ograničena veličina tijela zahtjeva (<c>[RequestSizeLimit]</c>),
///  - greška parsiranja (<c>JsonReaderException</c>) → 400 Bad Request.
/// </summary>
[ApiController]
[Route("api/lab05")]
public sealed class Lab05ImportController : ControllerBase
{
    private const int MaxDepth = 32;

    [HttpPost("import")]
    [RequestSizeLimit(64 * 1024)] // 64 KB
    public async Task<IActionResult> Import()
    {
        using var reader = new StreamReader(Request.Body);
        var body = await reader.ReadToEndAsync();

        JToken? token;
        try
        {
            token = JsonConvert.DeserializeObject<JToken>(body, new JsonSerializerSettings { MaxDepth = MaxDepth });
        }
        catch (JsonReaderException)
        {
            return BadRequest(new { error = $"Neispravan JSON ili preduboka struktura (najviše {MaxDepth} razina)." });
        }

        var (elements, depth) = JsonStats.Measure(token);
        return Ok(new { type = token?.Type.ToString(), elements, depth });
    }
}

/// <summary>Iterativno (bez rekurzije) broji elemente JSON stabla i mjeri njegovu dubinu.</summary>
public static class JsonStats
{
    public static (int Elements, int Depth) Measure(JToken? root)
    {
        if (root is null)
        {
            return (0, 0);
        }

        var elements = 0;
        var maxDepth = 0;
        var stack = new Stack<(JToken Token, int Depth)>();
        stack.Push((root, 1));
        while (stack.Count > 0)
        {
            var (token, depth) = stack.Pop();
            elements++;
            maxDepth = Math.Max(maxDepth, depth);
            foreach (var child in token.Children())
            {
                // JProperty je samo "omotač" para ime–vrijednost; brojimo njegovu vrijednost.
                var value = child is JProperty property ? property.Value : child;
                stack.Push((value, depth + 1));
            }
        }
        return (elements, maxDepth);
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab05"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab05"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab05]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab05` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab05*.
- **Rider:** *Unit Tests* → desni klik na `Lab05SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab05/Lab05SecurityTests.cs` i `Lab05FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

- `ApiIsCompiledAgainstPatchedNewtonsoftJson`: čita reference sklopa `VulnShop.Api`
  (`typeof(Program).Assembly.GetReferencedAssemblies()`) i traži `Newtonsoft.Json` verzije ≥ 13
  (12.0.3 ima *AssemblyVersion* 12.0.0.0, a 13.x ima 13.0.0.0).
- `DeeplyNestedJsonIsRejectedWithBadRequest`: JSON dubine 200 → `400`.

### b) Ponovljeni napad

`dotnet list package --vulnerable --include-transitive` više ne navodi `VulnShop.Api`, a build nema NU1903.
Zahtjevi 2) i 3) vraćaju `400`; DoS napad iz 4.3 odbija se s `413 Payload Too Large` (tijelo je veće od
64 kB), manji preduboki JSON vraća `400`, a aplikacija nastavlja raditi.

### c) Ponovno skeniranje

Ponovite `osv-scanner scan source -r .` / `trivy fs .` i usporedite izvještaj prije i poslije.
Izradite SBOM (`dotnet-CycloneDX SecureCodingAkademija.sln -o sbom`) i provjerite da sadrži `Newtonsoft.Json 13.0.3`.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** uključite zaključavanje verzija (`RestorePackagesWithLockFile`) u oba projekta, generirajte
`packages.lock.json` i u `.github/workflows/ci.yml` promijenite restore u `dotnet restore --locked-mode`.
Dodatno: napišite test koji provjerava da JSON dubine 33 vraća `400`, a dubine 30 `200`.

**Pitanja za razmišljanje:**

1. Zašto treba postaviti `MaxDepth` čak i nakon nadogradnje na verziju koja ima zadano ograničenje?
2. Koja je razlika između *ranjive* ovisnosti i *zlonamjerne* ovisnosti? Koje mjere štite od kojih?
3. Što je SBOM i kako ubrzava reakciju kada se objavi nova kritična ranjivost (npr. Log4Shell)?
