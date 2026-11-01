# Lab01 – Nesigurna izravna referenca na objekt (IDOR)

> **OWASP Top 10:2025:** A01 Broken Access Control · **CWE:** CWE-639 (Authorization Bypass Through
> User-Controlled Key) · **Endpoint:** `GET /api/lab01/orders/{id}` · **Zahtjevi:** `http/lab01.http`

## 1. Cilj vježbe

Prijavljeni korisnik može pročitati **tuđu** narudžbu (adresu dostave, stavke, iznos) samo promjenom broja
u URL-u. Naučit ćete prepoznati IDOR, iskoristiti ga i ispraviti provjerom vlasništva na poslužitelju te
testom dokazati da korisnik vidi samo svoje podatke.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab01/Lab01OrdersController.cs`, metoda `GetOrder(long id)` |
| Podaci | tablica `lab01_orders` (seed u `src/VulnShop.Api/Common/DbInitializer.cs`, `SeedLab01`): 1001 i 1002 (ana), 1003 (marko), 1004 (admin) |
| Prijava | `Common/AuthController.cs` (`POST /api/auth/login`), trenutni korisnik: `HttpContext.RequireCurrentUser()` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab01/Lab01SecurityTests.cs`, `Lab01FunctionalTests.cs` |

## 3. Opis ranjivosti

IDOR (*Insecure Direct Object Reference*) nastaje kada aplikacija koristi identifikator koji šalje klijent
(ID u URL-u, tijelu ili kolačiću) za dohvat objekta, a **ne provjerava smije li baš taj korisnik pristupiti
baš tom objektu**. Autentikacija (tko si) postoji – endpoint traži Bearer token – ali nedostaje
**autorizacija na razini objekta** (smiješ li vidjeti *ovu* narudžbu).

Broken Access Control je na prvom mjestu OWASP Top 10 liste od 2021. Stvarni primjeri: 2019. je kod
američke osiguravateljske kuće First American Financial jednostavnim mijenjanjem broja u URL-u bilo
dostupno oko 885 milijuna dokumenata s osobnim i financijskim podacima; brojni *bug bounty* nalazi na
velikim platformama su upravo IDOR-ovi (sekvencijalni ID-evi narudžbi, računa, poruka).

## 4. Eksploatacija – korak po korak

1. Pokrenite aplikaciju: `dotnet run --project src/VulnShop.Api --launch-profile http`.
2. Otvorite `http/lab01.http` i pošaljite zahtjev **1) Prijava kao ana**. Iz odgovora kopirajte `token` u `@token`.
3. Zahtjev **2)** – Ana čita svoju narudžbu `1001` → `200 OK`.
4. Zahtjev **3)** – Ana čita narudžbu `1003`, koja pripada Marku:

   ```http
   GET http://localhost:5080/api/lab01/orders/1003
   Authorization: Bearer <anin token>
   ```

   **Očekivani rezultat (dokaz ranjivosti):** `200 OK` s Markovom narudžbom:

   ```json
   {"id":1003,"owner":"marko","items":"Monitor","shippingAddress":"Savska 10, Zagreb","total":299.00}
   ```

5. Isto s curl (bash):

   ```bash
   TOKEN=<anin token>
   for id in 1001 1002 1003 1004; do curl -s http://localhost:5080/api/lab01/orders/$id -H "Authorization: Bearer $TOKEN"; echo; done
   ```

   PowerShell: `curl.exe -s http://localhost:5080/api/lab01/orders/1003 -H "Authorization: Bearer $token"`.
6. **Burp Suite:** pošaljite zahtjev 2) kroz Burpov preglednik ili proxy, u *HTTP history* desni klik →
   *Send to Repeater*, promijenite `1001` u `1003` → *Send*. Za sve ID-eve odjednom: *Send to Intruder*,
   označite broj kao `§1001§`, *Payload type: Numbers* od 1000 do 1010.

## 5. Analiza uzroka

```csharp
var rows = db.Query("SELECT ... FROM lab01_orders WHERE id = $id", ("$id", id));
...
// RANJIVO: nema provjere vlasništva – vraća se narudžba bilo kojeg korisnika.
var order = rows[0];
return Ok(new { ... });
```

Upit je ispravno parametriziran (nema SQL injectiona), ali jedini uvjet je `id` koji bira klijent.
Kontroler zna tko je prijavljen (`HttpContext.RequireCurrentUser()`), no tu informaciju ne koristi.
Atribut `[RequireAuth]` provjerava samo *je li* korisnik prijavljen, a ne *što* smije vidjeti.

## 6. Popravak

Smjernice:

- autorizaciju provodi **poslužitelj**, za **svaki** zahtjev i **svaki** objekt (ne oslanjajte se na to da
  klijent "ne zna" tuđi ID – ID-evi su predvidljivi, a i GUID-ovi procure),
- usporedite vlasnika objekta s prijavljenim korisnikom; iznimka je uloga ADMIN,
- za tuđi objekt vratite **404 Not Found** (kao da ne postoji), a ne 403 – tako ne otkrivate koji ID-evi postoje,
- alternativa: filtrirati već u upitu (`WHERE id = $id AND owner_username = $user`),
- u većim aplikacijama: politike autorizacije (`IAuthorizationService` + *resource-based authorization*).

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab01/Lab01OrdersController.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab01;

/// <summary>
/// Lab01 – A01 Broken Access Control: IDOR (CWE-639).
///
/// ISPRAVLJENO: nakon dohvata narudžbe provjerava se vlasništvo. Korisnik koji nije vlasnik
/// (i nije ADMIN) dobiva 404 – isto kao da narudžba ne postoji, kako se ne bi otkrivalo
/// koji identifikatori postoje.
/// </summary>
[ApiController]
[Route("api/lab01")]
[RequireAuth]
public sealed class Lab01OrdersController(Db db) : ControllerBase
{
    [HttpGet("orders/{id:long}")]
    public IActionResult GetOrder(long id)
    {
        var user = HttpContext.RequireCurrentUser();
        var rows = db.Query(
            "SELECT id, owner_username, items, shipping_address, total FROM lab01_orders WHERE id = $id",
            ("$id", id));

        // ISPRAVLJENO: provjera vlasništva na poslužitelju (ADMIN smije sve).
        // Tuđa narudžba → 404, jednako kao nepostojeća (ne otkrivamo postojanje).
        if (rows.Count == 0 || (rows[0].GetString("owner_username") != user.Username && !user.IsAdmin))
        {
            return NotFound(new { error = "Narudžba nije pronađena." });
        }

        var order = rows[0];
        return Ok(new
        {
            id = order.GetInt64("id"),
            owner = order.GetString("owner_username"),
            items = order.GetString("items"),
            shippingAddress = order.GetString("shipping_address"),
            total = order.GetDecimal("total"),
        });
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab01"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab01"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab01]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab01` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab01*.
- **Rider:** *Unit Tests* → desni klik na `Lab01SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab01/Lab01SecurityTests.cs` i `Lab01FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Ključni test (`UserCannotReadOrderOfAnotherUser`): Ana traži narudžbu 1003 i očekuje `404`, a tijelo ne
smije sadržavati Markovu adresu.

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju i pošaljite zahtjeve **3)** i **4)** iz `http/lab01.http`:
očekivano `404 Not Found` s `{"error":"Narudžba nije pronađena."}`. Zahtjev **2)** (vlastita narudžba)
i dalje vraća `200`, a administrator (prijava `admin` / `Admin123!`) i dalje vidi narudžbu 1003.

### c) Ponovno skeniranje

U Burp Intruderu ponovite napad s brojevima 1000–1010: Ana sada dobiva `200` samo za 1001 i 1002.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte endpoint `GET /api/lab01/orders` koji vraća popis narudžbi **samo** prijavljenog
korisnika (ADMIN vidi sve) i napišite sigurnosni test koji provjerava da Anin popis ne sadrži narudžbu 1003.

**Pitanja za razmišljanje:**

1. Zašto je za tuđu narudžbu bolje vratiti 404 nego 403? Postoje li situacije u kojima je 403 ispravniji?
2. Bi li prelazak s brojčanih ID-eva na GUID-ove riješio problem? Zašto ne bi trebao biti jedina mjera?
3. Kako biste sustavno osigurali da *novi* endpointi ne zaborave provjeru vlasništva (code review, politike, testovi)?
