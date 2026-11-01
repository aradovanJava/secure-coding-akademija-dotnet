# Lab15 – Pogrešno rukovanje iznimnim situacijama

> **OWASP Top 10:2025:** A10 Mishandling of Exceptional Conditions · **CWE:** CWE-636 (Not Failing Securely
> – "Failing Open"), CWE-755 (Improper Handling of Exceptional Conditions), CWE-209 (Error Message Containing
> Sensitive Information), CWE-460 (Improper Cleanup on Thrown Exception) · **Endpointi:**
> `GET /api/lab15/accounts`, `POST /api/lab15/transfer` · **Zahtjevi:** `http/lab15.http`

## 1. Cilj vježbe

Bankovni transfer ima dnevni limit od 1000 EUR, ali greška u provjeri limita se "proguta" (*fail-open*),
terećenje i odobrenje nisu u transakciji, a poruke grešaka otkrivaju nazive iznimki i SQL. Naučit ćete
načelo *fail-closed*, ispravno korištenje transakcija i generičkih poruka grešaka s korelacijskim ID-om.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab15/Lab15Controller.cs` – `Accounts`, `Transfer` |
| Provjera limita | `src/VulnShop.Api/Labs/Lab15/LimitService.cs` – `Check` baca `ArgumentException` (nepoznata valuta, neispravan iznos) ili `LimitExceededException` (**nije predmet popravka**) |
| Podaci | `lab15_accounts`: HR-ANA-001 (ana, 5000.00), HR-MARKO-001 (marko, 1000.00), HR-ADMIN-001 (admin, 10000.00) |
| Transakcije | `src/VulnShop.Api/Common/Db.cs` – `Use`, `QueryIn`, `ExecuteIn` (rad unutar `SqliteTransaction`) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab15/Lab15SecurityTests.cs`, `Lab15FunctionalTests.cs` |

## 3. Opis ranjivosti

Nova kategorija OWASP Top 10:2025 (A10) okuplja propuste koji nastaju kad program naiđe na neočekivano
stanje – iznimku, nedostupan servis, nepotpun podatak:

1. **Fail-open (CWE-636):** sigurnosna provjera ne uspije (iznimka), a kod nastavi kao da je uspjela. Napadač
   namjerno izaziva grešku u provjeri (nepoznata valuta) i tako zaobilazi limit.
2. **Nedosljedno stanje (CWE-460, CWE-755):** terećenje je izvršeno, odobrenje nije – novac nestaje.
   Operacije koje moraju uspjeti zajedno moraju biti u **transakciji**.
3. **Curenje informacija (CWE-209):** poruka greške s nazivom klase iznimke, SQL naredbom i nazivom tablice
   pomaže napadaču u sljedećem koraku.

Primjeri: sustavi za autorizaciju koji pri nedostupnosti servisa "propuste sve", 2FA koji se preskače kad
SMS servis ne odgovori, bankovni sustavi s nedosljednim stanjem nakon prekida.

## 4. Eksploatacija – korak po korak

Otvorite `http/lab15.http` i prijavite se kao `ana` (token u `@token`).

1. **2)** `GET /api/lab15/accounts` → `[{"accountNo":"HR-ANA-001","balance":5000.00}]`.
2. **3)** legitiman transfer 100 EUR → `200`.
3. **4)** 2000 EUR (iznad limita) → **`200`** – `LimitExceededException` je progutana.
4. **5)** fail-open s nepoznatom valutom:

   ```json
   {"fromAccount": "HR-ANA-001", "toAccount": "HR-MARKO-001", "amount": "50000.00", "currency": "XYZ"}
   ```

   → `200 {"status":"izvršeno","amount":50000.00,"currency":"XYZ"}`; Anin saldo je **negativan** (oko -47 000).
5. **6)** nepostojeći odredišni račun `HR-NEPOSTOJECI-999`, 100 EUR →

   ```json
   {"error":"System.InvalidOperationException: UPDATE lab15_accounts SET balance = balance + 100.00 WHERE account_no = 'HR-NEPOSTOJECI-999' -> 0 redaka (odredišni račun ne postoji)"}
   ```

   Ponovite 2): Anin saldo je **manji za 100**, a novac nije nigdje stigao. Poruka otkriva naziv iznimke, SQL i tablicu.
6. **7)** iznos `"sto eura"` → `500 {"error":"System.FormatException: The input string 'sto eura' was not in a correct format."}`.

**Burp Intruder / ZAP Fuzzer** na vrijednosti `currency` i `amount` (prazno, `null`, `-1`, `1e9`, `NaN`, vrlo
dugi niz) brzo otkriva koje vrijednosti uzrokuju iznimke i curenje informacija.

## 5. Analiza uzroka

```csharp
try { limitService.Check(amount, request.Currency); }
catch (Exception ex) { logger.LogDebug(...); }              // (1) FAIL-OPEN – greška = "prolaz"

db.Execute("UPDATE ... SET balance = $b WHERE account_no = $a", ...);   // terećenje
var to = db.Query(...);                                                 // (2) odobrenje izvan transakcije
if (to.Count == 0) throw new InvalidOperationException("UPDATE lab15_accounts ...");

catch (Exception ex)
{
    return StatusCode(500, new { error = ex.GetType().FullName + ": " + ex.Message });   // (3) curenje detalja
}
```

## 6. Popravak

- **Fail-closed:** svaka iznimka u sigurnosnoj provjeri znači **odbijanje** (`LimitExceededException` → 422,
  sve ostalo → 400). Nikad prazan `catch` oko sigurnosne logike.
- **Validacija unaprijed:** `decimal.TryParse` (InvariantCulture), iznos > 0 i najviše dvije decimale,
  valuta s allowliste (`LimitService.AllowedCurrencies`), različiti računi – greške se otkrivaju prije
  bilo kakve promjene stanja.
- **Transakcija** (`SqliteTransaction`): provjera oba računa, dostatnosti sredstava, terećenje i odobrenje –
  `Commit()` tek na kraju; bez `Commit()` se `Dispose()` pobrine za *rollback*.
- **Generičke poruke** (ProblemDetails) s **korelacijskim ID-om** (`HttpContext.TraceIdentifier`); detalji
  iznimke samo u logu (`logger.LogError(ex, ... correlationId ...)`). Globalno: `UseExceptionHandler` +
  ProblemDetails (vidi Lab04).

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab15/Lab15Controller.cs` (grana `rjesenja`):

```csharp
using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab15;

/// <summary>
/// Lab15 – A10 Mishandling of Exceptional Conditions (CWE-636, CWE-755, CWE-209, CWE-460).
///
/// ISPRAVLJENO:
///  (1) FAIL-CLOSED: svaka iznimka iz sigurnosne provjere (<see cref="LimitService.Check"/>) znači ODBIJANJE,
///  (2) validacija ulaza unaprijed (decimal, iznos &gt; 0, valuta s allowliste, različiti računi),
///  (3) terećenje i odobrenje u JEDNOJ transakciji (<c>SqliteTransaction</c>) – sve ili ništa,
///  (4) generičke poruke grešaka (ProblemDetails) s korelacijskim ID-om; detalji samo u logu.
/// </summary>
[ApiController]
[Route("api/lab15")]
[RequireAuth]
public sealed class Lab15Controller(Db db, LimitService limitService, ILogger<Lab15Controller> logger) : ControllerBase
{
    public sealed record TransferRequest(string? FromAccount, string? ToAccount, string? Amount, string? Currency);

    [HttpGet("accounts")]
    public IActionResult Accounts()
    {
        var user = HttpContext.RequireCurrentUser();
        var rows = db.Query(
            "SELECT account_no, balance FROM lab15_accounts WHERE owner_username = $u ORDER BY account_no",
            ("$u", user.Username));
        return Ok(rows.Select(r => new { accountNo = r.GetString("account_no"), balance = r.GetDecimal("balance") }));
    }

    [HttpPost("transfer")]
    public IActionResult Transfer([FromBody] TransferRequest request)
    {
        var user = HttpContext.RequireCurrentUser();

        // (2) Validacija ulaza unaprijed.
        if (string.IsNullOrWhiteSpace(request.FromAccount) || string.IsNullOrWhiteSpace(request.ToAccount) ||
            request.FromAccount == request.ToAccount ||
            !decimal.TryParse(request.Amount, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount) ||
            amount <= 0 || decimal.Round(amount, 2) != amount ||
            request.Currency is null || !LimitService.AllowedCurrencies.Contains(request.Currency))
        {
            return ProblemResult(StatusCodes.Status400BadRequest, "Neispravan zahtjev za transfer.");
        }

        // (1) FAIL-CLOSED: bilo kakva iznimka u sigurnosnoj provjeri = odbijanje.
        try
        {
            limitService.Check(amount, request.Currency);
        }
        catch (LimitExceededException)
        {
            return ProblemResult(StatusCodes.Status422UnprocessableEntity, "Iznos premašuje dnevni limit.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Provjera limita nije uspjela – transfer odbijen (fail-closed).");
            return ProblemResult(StatusCodes.Status400BadRequest, "Transfer nije dopušten.");
        }

        try
        {
            // (3) Terećenje i odobrenje u jednoj transakciji.
            return db.Use<IActionResult>(conn =>
            {
                using var tx = conn.BeginTransaction();

                var from = Db.QueryIn(conn, tx,
                    "SELECT balance FROM lab15_accounts WHERE account_no = $a AND owner_username = $o",
                    ("$a", request.FromAccount), ("$o", user.Username));
                var to = Db.QueryIn(conn, tx,
                    "SELECT balance FROM lab15_accounts WHERE account_no = $a", ("$a", request.ToAccount));
                if (from.Count == 0 || to.Count == 0)
                {
                    return ProblemResult(StatusCodes.Status404NotFound, "Račun nije pronađen.");
                }

                var fromBalance = from[0].GetDecimal("balance");
                if (fromBalance < amount)
                {
                    return ProblemResult(StatusCodes.Status422UnprocessableEntity, "Nedovoljno sredstava.");
                }

                Db.ExecuteIn(conn, tx, "UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                    ("$b", Money.ToDb(fromBalance - amount)), ("$a", request.FromAccount));
                Db.ExecuteIn(conn, tx, "UPDATE lab15_accounts SET balance = $b WHERE account_no = $a",
                    ("$b", Money.ToDb(to[0].GetDecimal("balance") + amount)), ("$a", request.ToAccount));

                tx.Commit(); // bez Commit() se transakcija pri Dispose() poništava (rollback)
                return Ok(new { status = "izvršeno", amount, currency = request.Currency });
            });
        }
        catch (Exception ex)
        {
            // (4) Detalji samo u logu; klijent dobiva generičku poruku i korelacijski ID.
            logger.LogError(ex, "Transfer nije uspio, correlationId={CorrelationId}", HttpContext.TraceIdentifier);
            return ProblemResult(StatusCodes.Status500InternalServerError, "Transfer trenutačno nije moguć.");
        }
    }

    /// <summary>Generički ProblemDetails odgovor s korelacijskim ID-om (bez internih detalja).</summary>
    private ObjectResult ProblemResult(int status, string title)
    {
        var problem = new ProblemDetails { Status = status, Title = title };
        problem.Extensions["correlationId"] = HttpContext.TraceIdentifier;
        return new ObjectResult(problem) { StatusCode = status };
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab15"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab15"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab15]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab15` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab15*.
- **Rider:** *Unit Tests* → desni klik na `Lab15SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab15/Lab15SecurityTests.cs` i `Lab15FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Svaki sigurnosni test pokreće vlastitu instancu aplikacije i mjeri saldo prije/poslije: 50 000 XYZ → 4xx i
nepromijenjen saldo; transfer na nepostojeći račun → 4xx i nepromijenjen saldo; tijelo greške ne sadrži
`Exception`, `UPDATE` ni `lab15_accounts`.

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju i ponovite 3)–7): 3) → `200`; 4) → `422 "Iznos premašuje dnevni limit."`;
5) → `400`; 6) → `404 "Račun nije pronađen."` i saldo nepromijenjen; 7) → `400`. Tijela grešaka izgledaju ovako:

```json
{"title":"Račun nije pronađen.","status":404,"correlationId":"0HN7..."}
```

### c) Ponovno skeniranje

Ponovite fuzzing polja `currency` i `amount`: nijedan odgovor nije `200` za neispravne vrijednosti i nijedan
ne sadrži nazive iznimki ili SQL. ZAP alarm *Application Error Disclosure* nestaje.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** napišite test koji dokazuje da transfer veći od raspoloživog salda vraća 4xx i ne mijenja
nijedan saldo: marko (saldo 1000.00) dvaput šalje 1000.00 EUR anu – prvi transfer uspijeva, drugi mora
vratiti 4xx, a salda oba računa moraju ostati kao nakon prvog. Zatim napišite test koji šalje
`"amount": "100.005"` i očekuje `400`.

**Pitanja za razmišljanje:**

1. Navedite primjer iz vlastitog iskustva gdje bi *fail-open* bio prihvatljiv (dostupnost važnija od sigurnosti), a gdje nikako.
2. Zašto je korelacijski ID koristan i korisniku i timu za podršku, a ne pomaže napadaču?
3. Što se događa s transakcijom ako se proces sruši između terećenja i odobrenja – u ranjivoj i u ispravljenoj verziji?
