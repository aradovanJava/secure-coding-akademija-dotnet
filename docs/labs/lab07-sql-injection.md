# Lab07 – SQL injection

> **OWASP Top 10:2025:** A05 Injection · **CWE:** CWE-89 (Improper Neutralization of Special Elements used in
> an SQL Command) · **Endpointi:** `GET /api/lab07/products/search?q=`, `POST /api/lab07/login` ·
> **Zahtjevi:** `http/lab07.http`

## 1. Cilj vježbe

Pretraga proizvoda i prijava grade SQL naredbu spajanjem stringova s korisničkim unosom. Iskoristit ćete
to za dohvat skrivenih proizvoda, čitanje druge tablice (UNION) i prijavu bez lozinke, a zatim propust
ukloniti **parametriziranim upitima** i to dokazati testovima.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab07/Lab07Controller.cs` – `Search`, `Login` |
| Podaci | `lab07_products` (Laptop, Miš, Tipkovnica, Monitor + skriveni "Interni prototip X", `hidden = 1`), `lab07_accounts` (admin / SuperTajna2026, webshop / Shop!2026 – lozinke **namjerno** u čistom tekstu) – seed u `DbInitializer.SeedLab07` |
| Pomoćna klasa baze | `src/VulnShop.Api/Common/Db.cs` – `Query(sql, params (string, object?)[])` (parametrizirani upiti) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab07/Lab07SecurityTests.cs`, `Lab07FunctionalTests.cs` |

## 3. Opis ranjivosti

Kad se korisnički unos umetne u tekst SQL naredbe, baza ne može razlikovati **podatak** od **koda**: znak `'`
zatvara string, a ostatak unosa postaje dio naredbe (`OR`, `UNION`, `--` komentar, `;`). Posljedice: čitanje
svih podataka, zaobilaženje prijave, izmjena/brisanje podataka, ponekad i izvršavanje naredbi na poslužitelju.

SQL injection je desetljećima među najčešćim i najskupljim propustima: Heartland Payment Systems (2008.,
~130 milijuna kartica), TalkTalk (2015.), MOVEit Transfer (2023., CVE-2023-34362 – SQLi kao ulaz za
masovnu krađu podataka stotina organizacija).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju i otvorite `http/lab07.http` (payloadi su već URL-kodirani).

1. **1)** `?q=Laptop` → jedan proizvod.
2. **2)** `?q='` → `400 {"error":"Greška u upitu."}` – jedan navodnik "pokvari" SQL: snažan signal SQLi-ja.
3. **3)** tautologija **`' OR '1'='1' --`** →

   ```sql
   SELECT id, name, description, price FROM lab07_products
   WHERE hidden = 0 AND name LIKE '%' OR '1'='1' --%'
   ```

   `AND` ima prednost pred `OR`, pa je uvjet `(hidden = 0 AND ...) OR '1'='1'` – istinit za **svaki** redak.
   U odgovoru je i `"Interni prototip X"` (dokaz ranjivosti).
   > Zašto `--` na kraju? Bez komentara (`%' OR '1'='1`) ostaje višak `%'` iz izvornog upita pa nastaje
   > uvjet `'1'='1%'`, koji je lažan – zato se u praksi preostatak naredbe "zakomentira".
4. **4)** varijanta `%' OR 1=1 --` – isti učinak.
5. **5)** UNION – čitanje druge tablice:

   ```text
   %' UNION SELECT id, username, password, 0 FROM lab07_accounts --
   ```

   Broj i tipovi stupaca moraju odgovarati izvornom SELECT-u (4 stupca). Odgovor sadrži
   `{"name":"admin","description":"SuperTajna2026",...}` i `webshop` / `Shop!2026`.
6. **7)** zaobilaženje prijave: korisničko ime **`admin'--`**, bilo koja lozinka →

   ```sql
   SELECT id, username FROM lab07_accounts WHERE username = 'admin'--' AND password = '...'
   ```

   Provjera lozinke je zakomentirana → `200 {"status":"prijavljen","username":"admin"}`.
7. **OWASP ZAP:** zahtjev 1) → desni klik → *Attack → Active Scan* (politika *Injection*) → alarm
   *SQL Injection - SQLite*. Ili *Fuzz* s listom *jbrofuzz → Injection → SQL Injection*.
   (Alat **sqlmap** automatizira cijeli postupak, ali ga u ovoj vježbi ne koristimo – cilj je razumjeti mehanizam.)

curl (bash): `curl -s -G "http://localhost:5080/api/lab07/products/search" --data-urlencode "q=' OR '1'='1' --"`

## 5. Analiza uzroka

```csharp
var sql = "SELECT id, name, description, price FROM lab07_products " +
          "WHERE hidden = 0 AND name LIKE '%" + q + "%'";                                  // RANJIVO
var sql = "SELECT id, username FROM lab07_accounts WHERE username = '" + u +
          "' AND password = '" + p + "'";                                                  // RANJIVO
```

Naredba se gradi konkatenacijom pa korisnik određuje njezinu **strukturu**. *Escapeanje* navodnika ručno
(`q.Replace("'", "''")`) je krhko (drugi konteksti, kodiranja, brojčani parametri bez navodnika) – nije popravak.

## 6. Popravak

- **Parametrizirani upiti** (`SqliteCommand.Parameters` – ovdje kroz `db.Query(sql, ("$p", vrijednost))`):
  tekst naredbe je konstantan, vrijednosti putuju odvojeno i baza ih nikad ne izvršava kao SQL.
- **LIKE**: parametar ne štiti od zamjenskih znakova `%` i `_` (korisnik bi mogao pretraživati "sve");
  escapeajte ih i dodajte `ESCAPE '\'`.
- **Validacija** duljine/formata ulaza (obrana u dubinu, ne zamjena za parametre).
- ORM (EF Core) i *stored procedure* parametriziraju automatski – osim kad se koristi `FromSqlRaw` /
  `ExecuteSqlRaw` sa spajanjem stringova (koristite `FromSqlInterpolated` / `FromSql`).
- **Najmanje ovlasti** (*least privilege*): aplikacijski korisnik baze bez prava na `DROP`, sistemske tablice, tuđe sheme.
- Lozinke u čistom tekstu (`lab07_accounts`) su zaseban propust – vidi Lab06.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab07/Lab07Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab07;

/// <summary>
/// Lab07 – A05 Injection: SQL injection (CWE-89).
///
/// ISPRAVLJENO: svi upiti su PARAMETRIZIRANI (<c>SqliteCommand.Parameters</c>) – korisnički unos
/// nikad ne postaje dio SQL naredbe, nego se šalje odvojeno kao podatak. Dodatno: escape
/// zamjenskih znakova za LIKE (<c>%</c>, <c>_</c>) i ograničenje duljine ulaza.
/// </summary>
[ApiController]
[Route("api/lab07")]
public sealed class Lab07Controller(Db db) : ControllerBase
{
    private const int MaxQueryLength = 100;

    public sealed record LoginRequest(string? Username, string? Password);

    [HttpGet("products/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        q ??= string.Empty;
        if (q.Length > MaxQueryLength)
        {
            return BadRequest(new { error = $"Upit može imati najviše {MaxQueryLength} znakova." });
        }

        // ISPRAVLJENO: parametar $pattern + escape znakova \, % i _ (LIKE ... ESCAPE '\').
        var pattern = "%" + q.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var rows = db.Query(
            "SELECT id, name, description, price FROM lab07_products " +
            "WHERE hidden = 0 AND name LIKE $pattern ESCAPE '\\'",
            ("$pattern", pattern));

        return Ok(rows.Select(r => new
        {
            id = r["id"],
            name = r["name"],
            description = r["description"],
            price = r["price"],
        }));
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password) ||
            request.Username.Length > 100 || request.Password.Length > 100)
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        // ISPRAVLJENO: parametrizirani upit.
        // (Lozinke u čistom tekstu i dalje su loša praksa – vidi Lab06; ovdje su zadržane radi vježbe.)
        var rows = db.Query(
            "SELECT id, username FROM lab07_accounts WHERE username = $u AND password = $p",
            ("$u", request.Username), ("$p", request.Password));
        if (rows.Count == 0)
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }
        return Ok(new { status = "prijavljen", username = rows[0].GetString("username") });
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab07"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab07"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab07]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab07` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab07*.
- **Rider:** *Unit Tests* → desni klik na `Lab07SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab07/Lab07SecurityTests.cs` i `Lab07FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi: tautologije `' OR '1'='1' --` i `%' OR 1=1 --` ne vraćaju "Interni prototip X"; UNION payload
vraća `200` (prazan popis) ili `400` i nikad `SuperTajna2026`/`webshop`; `admin'--` s bilo kojom lozinkom → `401`.

### b) Ponovljeni napad

Zahtjevi 3)–5) vraćaju `200 []` (traži se proizvod čije ime doslovno sadrži taj tekst), 2) vraća `200 []`
umjesto `400`, 7) i 8) vraćaju `401`. Legitimni zahtjevi 1) i 6) rade.

### c) Ponovno skeniranje

Ponovite ZAP *Active Scan* nad endpointima – alarm *SQL Injection* nestaje. `semgrep scan --config p/owasp-top-ten src/`
više ne prijavljuje SQL izgrađen iz stringova u `Lab07Controller.cs`.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte parametar `sort` (`name` ili `price`) u pretragu. Imena stupaca **ne mogu** biti SQL
parametri – riješite to allowlistom (`switch`) i napišite sigurnosni test koji šalje
`sort=price; DROP TABLE lab07_products--` i očekuje `400`.

**Pitanja za razmišljanje:**

1. Zašto parametrizirani upit štiti i od napada koje danas još ne poznajemo, a escapeanje ne?
2. Što je *blind* SQL injection i kako napadač izvlači podatke kad aplikacija ne prikazuje rezultat upita?
3. Kako bi *least privilege* korisnik baze ograničio štetu napada iz koraka 5)?
