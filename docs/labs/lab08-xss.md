# Lab08 – Cross-Site Scripting (XSS)

> **OWASP Top 10:2025:** A05 Injection · **CWE:** CWE-79 (Improper Neutralization of Input During Web Page
> Generation) · **Endpointi:** `GET /lab08/search?q=`, `POST /api/lab08/reviews`,
> `GET /lab08/products/{id}/reviews` · **Zahtjevi:** `http/lab08.http`

## 1. Cilj vježbe

Dvije HTML stranice ispisuju korisnički unos bez kodiranja: rezultati pretrage (**reflektirani** XSS) i
recenzije proizvoda (**pohranjeni** XSS). Izvršit ćete JavaScript u vlastitom pregledniku, ispraviti
ispis **kontekstualnim kodiranjem izlaza**, dodati Content-Security-Policy i testom potvrditi popravak.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab08/Lab08Controller.cs` – `Search`, `AddReview`, `Reviews` |
| Podaci | tablica `lab08_reviews` (product_id, author, text) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab08/Lab08SecurityTests.cs`, `Lab08FunctionalTests.cs` |

## 3. Opis ranjivosti

XSS je injection u **HTML/JavaScript** umjesto u SQL: preglednik ne razlikuje HTML koji je napisao
programer od HTML-a koji je ubacio napadač. Skripta se izvršava u kontekstu ranjive stranice (*same origin*)
pa može čitati kolačiće koji nisu `HttpOnly`, tokene iz `localStorage`, sadržaj stranice, slati zahtjeve u
ime korisnika, prikazati lažnu formu za prijavu …

- **Reflektirani:** payload je u URL-u; napadač žrtvi pošalje poveznicu.
- **Pohranjeni (stored):** payload je u bazi i izvršava se **svakom** posjetitelju stranice – opasniji.
- (**DOM-based:** ranjiv je JavaScript na klijentu – nije dio ove vježbe.)

Primjeri: crv *Samy* na MySpaceu (2005., milijun profila u 20 sati), XSS u eBayu i British Airwaysu
(Magecart, 2018. – skripta je krala podatke s platnih formi).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju. XSS se vidi tek u **pregledniku** (Chrome, Edge, Firefox).

1. Otvorite: `http://localhost:5080/lab08/search?q=Laptop` – normalna stranica.
2. Reflektirani XSS – otvorite u pregledniku:

   ```text
   http://localhost:5080/lab08/search?q=<script>alert(document.cookie)</script>
   ```

   **Očekivani rezultat:** iskače dijalog `alert` (prazan ili s kolačićima za `localhost`) – skripta iz
   URL-a se izvršila. Ako preglednik URL sam kodira, koristite zahtjev 2) iz `http/lab08.http`.
3. Varijanta bez oznake `<script>` (zaobilazi naivne filtere):
   `http://localhost:5080/lab08/search?q=<img src=x onerror=alert('XSS')>`
4. Pohranjeni XSS – pošaljite recenziju (zahtjev **4)**):

   ```http
   POST http://localhost:5080/api/lab08/reviews
   Content-Type: application/json

   {"productId": 1, "author": "Napadač", "text": "<img src=x onerror=alert('XSS')>"}
   ```

   i otvorite `http://localhost:5080/lab08/products/1/reviews` – `alert` se izvršava pri **svakom** otvaranju stranice.
5. U izvornom kodu stranice (Ctrl+U) vidi se nekodiran `<img src=x onerror=...>`.
6. **ZAP:** *Active Scan* nad `GET /lab08/search?q=test` → alarm *Cross Site Scripting (Reflected)*.
   **Burp:** Repeater – mijenjajte `q` i promatrajte gdje se unos pojavljuje u odgovoru (HTML kontekst).

## 5. Analiza uzroka

```csharp
"<h1>Rezultati pretrage za: " + q + "</h1>"                         // RANJIVO – reflektirani
html.Append(row.GetString("author")) ... .Append(row.GetString("text"))  // RANJIVO – pohranjeni
```

HTML se gradi spajanjem stringova, a unos nije kodiran za HTML kontekst. Recenzija se uz to sprema bez
ikakve validacije. Nema ni zaglavlja Content-Security-Policy koje bi pregledniku zabranilo inline skripte.

## 6. Popravak

- **Kodiranje izlaza** prema kontekstu: za HTML tijelo `HtmlEncoder.Default.Encode(...)`
  (`<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;`, `&` → `&amp;`). Kodira se pri **ispisu**,
  jer podaci u bazi mogu doći iz bilo kojeg izvora. Za atribute, JavaScript i URL-ove postoje drugi koderi
  (`JavaScriptEncoder`, `UrlEncoder`).
- **Validacija ulaza** (obavezna polja, najveća duljina) – obrana u dubinu, ne zamjena za kodiranje.
- **Content-Security-Policy:** `default-src 'self'; script-src 'self'; object-src 'none'` – preglednik ne
  izvršava inline skripte ni `onerror=` atribute čak i ako kodiranje negdje zakaže.
- Predlošci kodiraju automatski: Razor `@Model.Text`, Blazor, React `{text}`. Opasni su `Html.Raw(...)`,
  `MarkupString`, `dangerouslySetInnerHTML`, `innerHTML`.
- Kolačići sesije s `HttpOnly`, `Secure`, `SameSite`.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab08/Lab08Controller.cs` (grana `rjesenja`):

```csharp
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab08;

/// <summary>
/// Lab08 – A05 Injection: Cross-Site Scripting (CWE-79).
///
/// ISPRAVLJENO:
///  - svaki korisnički podatak koji se upisuje u HTML kodira se za HTML kontekst
///    (<see cref="HtmlEncoder"/>: &lt; → &amp;lt;, &gt; → &amp;gt;, " → &amp;quot; …),
///  - validacija ulaza (obavezna polja, najveća duljina),
///  - zaglavlje <c>Content-Security-Policy</c> kao druga linija obrane (zabranjuje inline skripte).
/// Napomena: Razor (<c>@izraz</c>) kodira automatski; <c>Html.Raw</c> zaobilazi kodiranje i opasan je.
/// </summary>
[ApiController]
public sealed class Lab08Controller(Db db) : ControllerBase
{
    private const string ContentSecurityPolicy = "default-src 'self'; script-src 'self'; object-src 'none'";

    public sealed record ReviewRequest(long ProductId, string? Author, string? Text);

    [HttpGet("/lab08/search")]
    public IActionResult Search([FromQuery] string? q)
    {
        q ??= string.Empty;
        if (q.Length > 100)
        {
            return BadRequest(new { error = "Upit može imati najviše 100 znakova." });
        }

        // ISPRAVLJENO: HTML kodiranje korisničkog unosa.
        var html = "<!DOCTYPE html><html lang=\"hr\"><head><meta charset=\"UTF-8\">" +
                   "<title>Pretraga</title></head><body>" +
                   "<h1>Rezultati pretrage za: " + HtmlEncoder.Default.Encode(q) + "</h1>" +
                   "<p>Nema pronađenih proizvoda.</p>" +
                   "</body></html>";
        return HtmlWithCsp(html);
    }

    [HttpPost("/api/lab08/reviews")]
    public IActionResult AddReview([FromBody] ReviewRequest request)
    {
        // ISPRAVLJENO: validacija ulaza.
        if (string.IsNullOrWhiteSpace(request.Author) || request.Author.Length > 50 ||
            string.IsNullOrWhiteSpace(request.Text) || request.Text.Length > 1000)
        {
            return BadRequest(new { error = "Autor (do 50 znakova) i tekst (do 1000 znakova) su obavezni." });
        }

        db.Execute(
            "INSERT INTO lab08_reviews (product_id, author, text) VALUES ($p, $a, $t)",
            ("$p", request.ProductId), ("$a", request.Author), ("$t", request.Text));
        return Ok(new { status = "spremljeno" });
    }

    [HttpGet("/lab08/products/{id:long}/reviews")]
    public IActionResult Reviews(long id)
    {
        var rows = db.Query(
            "SELECT author, text FROM lab08_reviews WHERE product_id = $p ORDER BY id", ("$p", id));

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html lang=\"hr\"><head><meta charset=\"UTF-8\">")
            .Append("<title>Recenzije</title></head><body>")
            .Append("<h1>Recenzije za proizvod ").Append(id).Append("</h1><ul>");
        foreach (var row in rows)
        {
            // ISPRAVLJENO: kodiranje pri ISPISU (podaci u bazi mogu biti zlonamjerni).
            html.Append("<li><strong>").Append(HtmlEncoder.Default.Encode(row.GetString("author"))).Append("</strong>: ")
                .Append(HtmlEncoder.Default.Encode(row.GetString("text"))).Append("</li>");
        }
        html.Append("</ul></body></html>");
        return HtmlWithCsp(html.ToString());
    }

    private ContentResult HtmlWithCsp(string html)
    {
        Response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
        return Content(html, "text/html; charset=utf-8");
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab08"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab08"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab08]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab08` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab08*.
- **Rider:** *Unit Tests* → desni klik na `Lab08SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab08/Lab08SecurityTests.cs` i `Lab08FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi: odgovor pretrage s `<script>alert(1)</script>` sadrži `&lt;script&gt;`, a ne izvornu oznaku;
pohranjena recenzija s `<img src=x onerror=...>` prikazuje se kao `&lt;img ...`; HTML odgovor ima
zaglavlje `Content-Security-Policy` sa `script-src`.

### b) Ponovljeni napad

Ponovno otvorite URL-ove iz koraka 2)–4) u pregledniku: umjesto dijaloga stranica **doslovno prikazuje**
tekst `<script>alert(document.cookie)</script>`. U izvornom kodu stranice vidi se `&lt;script&gt;...`.
U alatima za razvojne programere (F12 → *Network* → odgovor → *Headers*) vidi se zaglavlje CSP.
Napomena: recenzije spremljene prije popravka i dalje su u bazi, ali se sada sigurno prikazuju.

### c) Ponovno skeniranje

Ponovite ZAP *Active Scan* – alarm *Cross Site Scripting (Reflected)* i *CSP Header Not Set* za `/lab08/...` nestaju.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte u stranicu pretrage poveznicu `<a href="/lab08/search?q=...">Ponovi pretragu</a>` u kojoj je
`q` dio URL-a u atributu `href`. Odaberite ispravan način kodiranja (URL + HTML atribut) i napišite test s
payloadom `" onmouseover="alert(1)` koji dokazuje da napadač ne može izaći iz atributa.

**Pitanja za razmišljanje:**

1. Zašto se kodira pri **ispisu**, a ne (samo) pri spremanju u bazu?
2. Što CSP `script-src 'self'` sprječava, a što ne? Je li CSP dovoljan bez kodiranja izlaza?
3. Kako bi napadač iskoristio pohranjeni XSS da preuzme sesiju administratora koji pregledava recenzije?
