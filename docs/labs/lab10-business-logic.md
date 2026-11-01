# Lab10 – Nesiguran dizajn: propusti u poslovnoj logici

> **OWASP Top 10:2025:** A06 Insecure Design · **CWE:** CWE-840 (Business Logic Errors), CWE-20 (Improper
> Input Validation) · **Endpointi:** `GET /api/lab10/wallet`, `POST /api/lab10/checkout` ·
> **Zahtjevi:** `http/lab10.http`

## 1. Cilj vježbe

Naplata u web trgovini vjeruje klijentu: cijeni, količini i popisu kupona. Kupit ćete laptop za 0,01 EUR,
negativnom količinom **povećati** stanje novčanika i "nagomilati" popuste. Naučit ćete da se poslovna pravila
provode na poslužitelju, kako ih modelirati (*abuse cases*, STRIDE) i kako ih zaključati testovima.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab10/Lab10Controller.cs` – `Wallet`, `Checkout` |
| Modeli zahtjeva | `CheckoutItem(ProductId, Quantity, UnitPrice)`, `CheckoutRequest(Items, CouponCodes)` |
| Podaci | `lab10_wallets` (ana, marko, admin – po 1000.00 EUR), `lab10_products` (1 Laptop 899.00, 2 Slušalice 99.00, 3 Kabel 9.99), `lab10_coupon_usage` (prazna) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab10/Lab10SecurityTests.cs`, `Lab10FunctionalTests.cs` |

Kupon `AKADEMIJA10` daje 10 % popusta i smije se iskoristiti jednom.

## 3. Opis ranjivosti

Za razliku od injectiona, ovdje nema "neispravnog znaka" ni skenera koji će propust sigurno naći: svaki
zahtjev je sintaktički valjan. Propust je u **dizajnu** – pretpostavka da će klijent (preglednik, mobilna
aplikacija) slati samo razumne vrijednosti. Napadač zaobilazi korisničko sučelje i šalje vlastite zahtjeve
(Burp, curl). Kategorija A06 naglašava da se ovakvi propusti sprječavaju **prije pisanja koda**: modeliranjem
prijetnji (STRIDE: *Tampering* s cijenom), *abuse case* scenarijima ("što ako je količina negativna?") i
sigurnosnim zahtjevima u specifikaciji.

Primjeri iz prakse: trgovine koje su prihvaćale cijenu iz skrivenog polja forme, negativne količine u
košarici, beskonačno korištenje kupona za dobrodošlicu, *race condition* kod dvostrukog trošenja istog salda.

## 4. Eksploatacija – korak po korak

Otvorite `http/lab10.http`, prijavite se kao `ana` (zahtjev **1)**) i kopirajte token u `@token`.

1. **2)** `GET /api/lab10/wallet` → `{"username":"ana","balance":1000.00}`.
2. **3)** legitimno: 2 × kabel → `charged: 19.98`.
3. **4)** cijena koju bira klijent:

   ```json
   {"items": [{"productId": 1, "quantity": 1, "unitPrice": 0.01}], "couponCodes": []}
   ```

   → `{"charged":0.01, ...}` – **laptop za jedan cent**.
4. **5)** negativna količina:

   ```json
   {"items": [{"productId": 1, "quantity": -5, "unitPrice": 899.00}], "couponCodes": []}
   ```

   → `{"charged":-4495.00, "balance": ...}` – stanje novčanika **naraslo** za 4495 EUR.
5. **6)** isti kupon tri puta (`["AKADEMIJA10","AKADEMIJA10","AKADEMIJA10"]`) za slušalice od 99.00 →
   `charged: 72.17` (0,9³ = 27,1 % popusta umjesto 10 %).
6. **7)** stanje novčanika nakon napada.

**Burp Repeater** je idealan: uhvatite legitiman checkout i mijenjajte `unitPrice`, `quantity`, `couponCodes`.

## 5. Analiza uzroka

```csharp
total += item.UnitPrice * item.Quantity;          // cijena i količina od klijenta, bez provjere
foreach (var coupon in request.CouponCodes ...)   // svaki kupon, i ponovljeni
    total *= 0.90m;
var newBalance = GetBalance(user.Username) - total;   // nema provjere total > 0 ni dostatnog stanja
db.Execute("UPDATE lab10_wallets SET balance = $b ...");  // nema transakcije
```

Poslužitelj ima sve podatke (cijene u `lab10_products`, iskorištene kupone, stanje), ali ih ne koristi – a
tipovi podataka (`int`, `decimal`) ne izražavaju pravila domene (količina 1..10, iznos > 0).

## 6. Popravak

- **Cijene iz baze**; `unitPrice` iz zahtjeva se ignorira (izbačen iz DTO-a).
- **Validacija pravila domene:** 1–20 stavki, količina 1..10, samo postojeći proizvodi.
- **Kuponi:** najviše jedan po narudžbi, poznat kod, **jednokratna uporaba po korisniku** (`lab10_coupon_usage`).
- **Iznos** mora biti > 0 i pokriven stanjem novčanika.
- **Transakcija:** čitanje cijena, zapis o kuponu i terećenje izvode se zajedno (sve ili ništa).
- Proces: modeliranje prijetnji (STRIDE), *abuse cases* uz svaku korisničku priču, testovi za granične vrijednosti.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab10/Lab10Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab10;

/// <summary>
/// Lab10 – A06 Insecure Design: poslovna logika (CWE-840, CWE-20).
///
/// ISPRAVLJENO (pravila poslovne logike provodi POSLUŽITELJ):
///  - cijena se uzima iz baze (<c>lab10_products</c>), a <c>unitPrice</c> iz zahtjeva se ignorira,
///  - količina 1..10, barem jedna stavka, poznati proizvodi,
///  - najviše jedan kupon po narudžbi i jednokratna uporaba kupona po korisniku,
///  - ukupni iznos mora biti &gt; 0 i pokriven stanjem novčanika,
///  - terećenje, zapis o kuponu i provjere izvode se u jednoj transakciji.
/// </summary>
[ApiController]
[Route("api/lab10")]
[RequireAuth]
public sealed class Lab10Controller(Db db) : ControllerBase
{
    private const string Coupon = "AKADEMIJA10";
    private const decimal CouponFactor = 0.90m;

    /// <summary>ISPRAVLJENO: klijent šalje samo proizvod i količinu (eventualni unitPrice se ignorira).</summary>
    public sealed record CheckoutItem(long ProductId, int Quantity);

    public sealed record CheckoutRequest(List<CheckoutItem>? Items, List<string>? CouponCodes);

    [HttpGet("wallet")]
    public IActionResult Wallet()
    {
        var user = HttpContext.RequireCurrentUser();
        var balance = Money.Parse(db.Scalar("SELECT balance FROM lab10_wallets WHERE username = $u", ("$u", user.Username)));
        return Ok(new { username = user.Username, balance });
    }

    [HttpPost("checkout")]
    public IActionResult Checkout([FromBody] CheckoutRequest request)
    {
        var user = HttpContext.RequireCurrentUser();
        var items = request.Items ?? new List<CheckoutItem>();
        var coupons = request.CouponCodes ?? new List<string>();

        // ISPRAVLJENO: validacija ulaza prije bilo kakve promjene stanja.
        if (items.Count is < 1 or > 20 || items.Any(i => i.Quantity is < 1 or > 10))
        {
            return BadRequest(new { error = "Narudžba mora imati 1–20 stavki, a količina mora biti 1–10." });
        }
        if (coupons.Count > 1)
        {
            return BadRequest(new { error = "Dopušten je najviše jedan kupon po narudžbi." });
        }
        if (coupons.Count == 1 && !string.Equals(coupons[0], Coupon, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new { error = "Nepoznat kupon." });
        }

        return db.Use<IActionResult>(conn =>
        {
            using var tx = conn.BeginTransaction();

            // ISPRAVLJENO: cijene iz baze, ne iz zahtjeva.
            var total = 0m;
            foreach (var item in items)
            {
                var product = Db.QueryIn(conn, tx, "SELECT price FROM lab10_products WHERE id = $id", ("$id", item.ProductId));
                if (product.Count == 0)
                {
                    return BadRequest(new { error = "Nepoznat proizvod." });
                }
                total += product[0].GetDecimal("price") * item.Quantity;
            }

            if (coupons.Count == 1)
            {
                // ISPRAVLJENO: kupon se smije iskoristiti samo jednom po korisniku.
                var used = Db.QueryIn(conn, tx,
                    "SELECT 1 FROM lab10_coupon_usage WHERE username = $u AND coupon = $c",
                    ("$u", user.Username), ("$c", Coupon));
                if (used.Count > 0)
                {
                    return BadRequest(new { error = "Kupon je već iskorišten." });
                }
                Db.ExecuteIn(conn, tx, "INSERT INTO lab10_coupon_usage (username, coupon) VALUES ($u, $c)",
                    ("$u", user.Username), ("$c", Coupon));
                total *= CouponFactor;
            }
            total = Math.Round(total, 2, MidpointRounding.AwayFromZero);

            var balance = Db.QueryIn(conn, tx, "SELECT balance FROM lab10_wallets WHERE username = $u", ("$u", user.Username))[0]
                .GetDecimal("balance");
            if (total <= 0 || total > balance)
            {
                return BadRequest(new { error = "Iznos nije valjan ili stanje novčanika nije dostatno." });
            }

            var newBalance = balance - total;
            Db.ExecuteIn(conn, tx, "UPDATE lab10_wallets SET balance = $b WHERE username = $u",
                ("$b", Money.ToDb(newBalance)), ("$u", user.Username));
            tx.Commit();
            return Ok(new { charged = total, balance = newBalance });
        });
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab10"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab10"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab10]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab10` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab10*.
- **Rider:** *Unit Tests* → desni klik na `Lab10SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab10/Lab10SecurityTests.cs` i `Lab10FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Svaki sigurnosni test pokreće **vlastitu instancu aplikacije** (`new VulnShopFactory()`), jer mijenja stanje
novčanika, i mjeri razliku stanja prije/poslije: količina -5 → `400` i nepromijenjeno stanje; `unitPrice`
0.01 za laptop → naplaćeno točno 899.00 (ili `400`); trostruki kupon → `400` ili popust samo jednom (809.10).

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju: zahtjev 4) naplaćuje **899.00**, 5) i 6) vraćaju `400`. Zahtjev 8) (jedan
kupon) uspije prvi put (`charged: 89.10`), a drugi put vraća `400 "Kupon je već iskorišten."`.

### c) Ponovno skeniranje

Automatski skeneri ovakve propuste rijetko pronalaze. Provjera je ručna (Burp Repeater s istim
zahtjevima) i – najvažnije – **testovi** koji opisuju pravila poslovne logike.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** napišite test koji dokazuje da kupnja koja premašuje stanje novčanika (npr. 2 × laptop za anu)
vraća `400` i ne mijenja stanje. Zatim razmislite o *race conditionu*: što bi se dogodilo kad bi dva
zahtjeva s istim kuponom stigla istodobno? Kako transakcija (i jedinstveni indeks na `lab10_coupon_usage`) pomaže?

**Pitanja za razmišljanje:**

1. Zašto skener ranjivosti (ZAP, Burp Scanner) teško pronalazi propuste u poslovnoj logici?
2. Napišite tri *abuse case* scenarija za funkciju "povrat novca" (refund) u web trgovini.
3. Koje kategorije STRIDE modela pokrivaju napadi iz ove vježbe?
