# Lab13 – Nesigurna deserijalizacija

> **OWASP Top 10:2025:** A08 Software or Data Integrity Failures · **CWE:** CWE-502 (Deserialization of
> Untrusted Data) · **Endpoint:** `POST /api/lab13/cart/import` · **Zahtjevi:** `http/lab13.http`

## 1. Cilj vježbe

Uvoz košarice deserijalizira JSON Newtonsoft.Json-om uz `TypeNameHandling.All`, pa **klijent bira koja će se
.NET klasa instancirati** (svojstvo `$type`). Iskoristit ćete "gadget" klasu `DiagnosticsTask`, čiji se kod
izvršava tijekom deserijalizacije i zapisuje (bezopasnu) marker datoteku. Popravak: fiksni DTO bez
polimorfizma, strogo parsiranje i validacija.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Ranjivi endpoint | `src/VulnShop.Api/Labs/Lab13/Lab13Controller.cs`, metoda `Import` |
| Legitimne klase | `src/VulnShop.Api/Labs/Lab13/Cart.cs` (`Cart`, `CartItem`) |
| Gadget | `src/VulnShop.Api/Labs/Lab13/DiagnosticsTask.cs` – `[OnDeserialized]` zapisuje `Content` u `ReportPath` (**nije predmet popravka**) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab13/Lab13SecurityTests.cs`, `Lab13FunctionalTests.cs` |

## 3. Opis ranjivosti

Deserijalizacija pretvara podatke (bajtove, JSON, XML) natrag u objekte. Ako format sadrži **naziv tipa**
(`$type` u Newtonsoftu uz `TypeNameHandling` ≠ `None`, `BinaryFormatter`, Java `ObjectInputStream`), napadač
određuje koji će se konstruktori, *setteri* i *callbackovi* (`[OnDeserialized]`) izvršiti – i to **prije** nego
što aplikacija provjeri što je dobila. Lanci takvih klasa u .NET okviru i popularnim bibliotekama
(*gadget chains*, npr. `ObjectDataProvider`, `WindowsIdentity`) omogućuju pokretanje procesa; alat
**ysoserial.net** sadrži gotove lance. U ovoj vježbi gadget je namjerno bezopasan: zapisuje tekstualnu datoteku.

Zbog toga je Microsoft `BinaryFormatter` proglasio opasnim i **uklonio iz .NET 9**, a za Newtonsoft
upozorava da `TypeNameHandling` mora biti `None` za nepouzdane podatke (analizatori CA2326/CA2327).
Primjeri: CVE-2019-0604 (SharePoint), Exchange ProxyShell lanac, brojni napadi na Javine aplikacije (Apache
Commons Collections, 2015.).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju i otvorite `http/lab13.http`.

1. **1)** legitimna košarica (2 stavke) → `200 {"status":"ok","itemCount":2}`.
2. **2)** ista košarica s `"$type": "VulnShop.Api.Labs.Lab13.Cart, VulnShop.Api"` – ranjiva verzija poštuje
   tip koji je zadao klijent.
3. **3)/4)** napad – klijent traži klasu `DiagnosticsTask`:

   ```json
   {"$type": "VulnShop.Api.Labs.Lab13.DiagnosticsTask, VulnShop.Api",
    "ReportPath": "/tmp/vulnshop-lab13.txt", "Content": "PWNED"}
   ```

   (Windows: `"ReportPath": "C:\\Temp\\vulnshop-lab13.txt"` – mapa `C:\Temp` mora postojati.)

   **Očekivani rezultat:** `200 {"status":"ok","type":"DiagnosticsTask"}` i **datoteka postoji**:

   ```bash
   cat /tmp/vulnshop-lab13.txt          # PWNED
   ```

   PowerShell: `Get-Content C:\Temp\vulnshop-lab13.txt`. Aplikacija je "odbila" objekt (nije košarica),
   ali kod gadgeta se već izvršio.
4. **Burp Repeater:** mijenjajte vrijednost `$type`. Nepostojeći tip vraća `400`, a postojeći, npr.
   `{"$type": "System.Object, System.Private.CoreLib"}`, vraća `200 {"type":"Object"}` – razlika otkriva
   da poslužitelj stvarno učitava klasu koju je zadao klijent (signal za napadača).

## 5. Analiza uzroka

```csharp
var obj = JsonConvert.DeserializeObject(body, new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All,    // RANJIVO: tip bira klijent ($type)
});
```

Poziv bez ciljnog tipa + `TypeNameHandling.All` = "napravi bilo koji objekt koji JSON zatraži". Provjera
`obj is Cart` dolazi **nakon** deserijalizacije – prekasno.

## 6. Popravak

- **Tip određuje poslužitelj:** deserijalizacija isključivo u konkretan DTO (`CartImportRequest`), bez
  `TypeNameHandling` (ovdje System.Text.Json, koji ne instancira proizvoljne klase prema `$type`).
- **Strogo parsiranje:** nepoznata svojstva su greška (`JsonUnmappedMemberHandling.Disallow`), ograničena dubina
  i veličina tijela; greška → `400`.
- **Validacija sadržaja** (1–50 stavki, količina 1–10).
- Ako polimorfizam stvarno treba: Newtonsoft `TypeNameHandling.None` + `ISerializationBinder` s **allowlistom**
  dopuštenih tipova, ili System.Text.Json `[JsonPolymorphic]` / `[JsonDerivedType]` (eksplicitno navedeni podtipovi).
- Ako podaci putuju preko klijenta i vraćaju se: potpis (HMAC) kako bi se otkrila izmjena.
- Nikad `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter` za nepouzdane podatke.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab13/Lab13Controller.cs` (grana `rjesenja`):

```csharp
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab13;

/// <summary>
/// Lab13 – A08 Software or Data Integrity Failures: nesigurna deserijalizacija (CWE-502).
///
/// ISPRAVLJENO:
///  - tip objekta određuje POSLUŽITELJ, ne klijent: deserijalizira se isključivo u konkretan DTO
///    (<see cref="CartImportRequest"/>) pomoću System.Text.Json, koji ne podržava "$type" za
///    proizvoljne klase,
///  - nepoznata svojstva (npr. "$type", "ReportPath") su greška (<c>JsonUnmappedMemberHandling.Disallow</c>),
///  - validacija sadržaja (1–50 stavki, količina 1–10) → inače 400.
/// Ako polimorfizam baš treba (Newtonsoft): <c>TypeNameHandling.None</c> ili <c>ISerializationBinder</c>
/// s allowlistom dopuštenih tipova.
/// </summary>
[ApiController]
[Route("api/lab13")]
public sealed class Lab13Controller : ControllerBase
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8,
    };

    /// <summary>DTO za uvoz košarice – samo podaci, bez ponašanja.</summary>
    public sealed record CartImportRequest(string? Owner, List<CartItemDto>? Items);

    public sealed record CartItemDto(long ProductId, string? Name, int Quantity);

    [HttpPost("cart/import")]
    [RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> Import()
    {
        CartImportRequest? request;
        try
        {
            // ISPRAVLJENO: fiksni ciljni tip (DTO), bez TypeNameHandling.
            request = await JsonSerializer.DeserializeAsync<CartImportRequest>(Request.Body, Options);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return BadRequest(new { error = "Neispravan sadržaj košarice." });
        }

        if (request?.Items is not { Count: >= 1 and <= 50 } items || items.Any(i => i.Quantity is < 1 or > 10))
        {
            return BadRequest(new { error = "Košarica mora imati 1–50 stavki s količinom 1–10." });
        }

        var cart = new Cart
        {
            Owner = request.Owner,
            Items = items.Select(i => new CartItem { ProductId = i.ProductId, Name = i.Name, Quantity = i.Quantity }).ToList(),
        };
        return Ok(new { status = "ok", itemCount = cart.Items.Count });
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab13"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab13"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab13]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab13` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab13*.
- **Rider:** *Unit Tests* → desni klik na `Lab13SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab13/Lab13SecurityTests.cs` i `Lab13FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Test sam gradi napadni JSON s `$type` koji traži `DiagnosticsTask` i putanjom marker datoteke u privremenom
direktoriju (`Path.GetTempPath()`), a zatim provjerava: datoteka **ne postoji** i odgovor je `400`.

### b) Ponovljeni napad

Obrišite marker datoteku i ponovite zahtjeve 3)/4): odgovor je `400 {"error":"Neispravan sadržaj košarice."}`
i datoteka ne nastaje. Zahtjev 1) i dalje vraća `itemCount: 2`; zahtjev 2) (s `$type`) sada vraća `400` –
klijent više ne smije zadavati tipove.

### c) Ponovno skeniranje

Uključite Roslyn analizatore (`<AnalysisMode>All</AnalysisMode>`, vidi `docs/01-alati.md`) – upozorenja
CA2326/CA2327 za `Lab13Controller.cs` nestaju. `semgrep scan --config p/csharp src/` više ne prijavljuje `TypeNameHandling.All`.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** napišite Newtonsoft varijantu popravka s `ISerializationBinder` koji dopušta samo `Cart` i
`CartItem` (sve ostalo baca `JsonSerializationException`) i test koji dokazuje da je `DiagnosticsTask` odbijen,
a `Cart` s `$type` prihvaćen.

**Pitanja za razmišljanje:**

1. Zašto provjera tipa **nakon** deserijalizacije (`obj is Cart`) ne štiti?
2. Zašto je allowlista tipova sigurnija od blockliste "opasnih" klasa?
3. Gdje se u vašim projektima podaci deserijaliziraju (poruke iz redova čekanja, cache, kolačići, datoteke)? Jesu li ti izvori pouzdani?
