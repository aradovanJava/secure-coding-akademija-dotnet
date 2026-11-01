# Lab03 – Server-Side Request Forgery (SSRF)

> **OWASP Top 10:2025:** A01 Broken Access Control (u izdanju 2025. SSRF je dio kategorije A01) ·
> **CWE:** CWE-918 · **Endpoint:** `GET /api/lab03/preview?url=...` · **Zahtjevi:** `http/lab03.http`

## 1. Cilj vježbe

Funkcija "pregled poveznice" natjera poslužitelj da dohvati URL koji je zadao korisnik. Napadač je
iskorištava kako bi poslužitelj u njegovo ime pristupio **internim** servisima – ovdje endpointu s tajnama
koji je dostupan samo s loopback adrese. Naučit ćete validirati odredište (shema, razrješavanje DNS-a,
blokiranje internih raspona) i to dokazati testom.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Ranjivi endpoint | `src/VulnShop.Api/Labs/Lab03/Lab03PreviewController.cs`, metoda `Preview` |
| Meta napada | `src/VulnShop.Api/Labs/Lab03/InternalController.cs` – `GET /internal/admin/secrets` (vraća tajne samo za loopback; **nije predmet popravka**) |
| Testovi | `tests/VulnShop.Tests/Labs/Lab03/Lab03SecurityTests.cs`, `Lab03FunctionalTests.cs` |

## 3. Opis ranjivosti

Kod SSRF-a napadač ne napada interni sustav izravno – nema mrežni pristup – nego koristi **poslužitelj kao
posrednika**. Poslužitelj se obično nalazi u "povjerljivoj" zoni: vidi `localhost`, internu mrežu
(10.x, 172.16–31.x, 192.168.x), administrativna sučelja, baze i – u oblaku – **metadata servis**
`http://169.254.169.254/`, koji izdaje privremene vjerodajnice instance.

Stvarni incident: 2019. je napadačica preko SSRF-a u pogrešno konfiguriranom WAF-u dohvatila vjerodajnice
s AWS metadata servisa i iz S3-a preuzela podatke o više od 100 milijuna klijenata banke Capital One.
Zbog toga AWS danas preporučuje IMDSv2 (traži poseban token), a OWASP Top 10:2025 SSRF svrstava u A01.

## 4. Eksploatacija – korak po korak

1. Pokrenite aplikaciju (`--launch-profile http`, port **5080**) i otvorite `http/lab03.http`.
2. **1)** prijava kao `ana` → token u `@token`.
3. **2)** legitimno: `?url=https://example.com` → `200` s početkom HTML-a stranice.
4. **4)** napad – poslužitelj sam sebi šalje zahtjev:

   ```http
   GET http://localhost:5080/api/lab03/preview?url=http://127.0.0.1:5080/internal/admin/secrets
   Authorization: Bearer <anin token>
   ```

   **Očekivani rezultat (dokaz ranjivosti):**

   ```json
   {"url":"http://127.0.0.1:5080/internal/admin/secrets","status":200,
    "content":"{\"dbPassword\":\"Sup3rTajn0!\",\"paymentApiKey\":\"sk_live_akademija_123\"}"}
   ```

   Interni endpoint je "vidio" zahtjev s adrese 127.0.0.1 i povjerovao mu.
5. **5)–6)** isto preko `localhost` i `[::1]` (IPv6 loopback) – zaobilaženje naivnih provjera tipa
   `if (url.Contains("127.0.0.1"))`.
6. **7)** `http://169.254.169.254/latest/meta-data/` – na lokalnom računalu obično istek vremena (502),
   ali u oblaku (AWS, Azure, GCP) bi vratio podatke o instanci.
7. **Burp Intruder / ZAP Fuzzer:** zamijenite port u `http://127.0.0.1:§5080§/` listom portova
   (22, 80, 443, 1433, 3306, 5432, 6379, 8080 …) – razlike u odgovoru (502 / timeout / 200) otkrivaju koji
   interni servisi postoje (*port scanning* kroz SSRF).

curl: `curl -s "http://localhost:5080/api/lab03/preview?url=http://127.0.0.1:5080/internal/admin/secrets" -H "Authorization: Bearer $TOKEN"`

> **Napomena o testovima:** testovi pokreću aplikaciju u memoriji (TestServer), bez stvarnog TCP porta, pa
> ranjivi kod u testu ne može dohvatiti tajne (dobije grešku spajanja → 502). Sigurnosni test zato traži
> da ispravan kod takav URL **odbije prije dohvata** s `400 Bad Request` i da tijelo ne sadrži `Sup3rTajn0!`.

## 5. Analiza uzroka

```csharp
private static readonly HttpClient Client = new(new SocketsHttpHandler { AllowAutoRedirect = true, ... });
...
target = new Uri(url, UriKind.Absolute);
using var response = await Client.GetAsync(target);   // RANJIVO: bez ikakve provjere odredišta
```

Jedina provjera je da je URL sintaktički ispravan. Ne provjerava se shema, host, IP adresa u koju se host
razrješava ni preusmjeravanja (napadač može dati javni URL koji vraća `302 Location: http://127.0.0.1/...`).

## 6. Popravak

- **Shema:** dopuštene samo `http` i `https` (bez `file:`, `ftp:`, `gopher:` …).
- **Odredište:** razriješite host (DNS) i odbijte ako je **bilo koja** adresa loopback (127.0.0.0/8, ::1),
  privatna (10/8, 172.16/12, 192.168/16, fc00::/7), link-local (169.254/16 – cloud metadata, fe80::/10),
  `0.0.0.0`, multicast i rezervirano. Vratite `400`.
- **DNS rebinding:** provjeru ponovite u trenutku spajanja (`SocketsHttpHandler.ConnectCallback`) i spojite se
  baš na provjerenu IP adresu – inače DNS između provjere i spajanja može vratiti drugu (internu) adresu.
- **Preusmjeravanja isključena** (`AllowAutoRedirect = false`), kratak timeout, ograničena veličina odgovora.
- Gdje god je moguće: **allowlista domena** (npr. samo partnerski servisi) – najjača mjera.
- Mrežna razina (obrana u dubinu): odlazni vatrozid / egress proxy, IMDSv2 u AWS-u.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab03/Lab03PreviewController.cs` (grana `rjesenja`):

```csharp
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab03;

/// <summary>
/// Lab03 – A01 Broken Access Control: Server-Side Request Forgery (CWE-918).
///
/// ISPRAVLJENO:
///  - dopuštene su samo sheme http i https,
///  - host se razrješava (DNS) i odbija se svaka adresa koja nije javna: loopback, privatne mreže
///    (10/8, 172.16/12, 192.168/16), link-local (169.254/16 – cloud metadata), 0.0.0.0, ::1,
///    fc00::/7, fe80::/10 …,
///  - ista se provjera ponavlja u trenutku spajanja (<c>ConnectCallback</c>) – zaštita od DNS rebindinga,
///  - preusmjeravanja su isključena, uz kratki timeout i ograničenje veličine odgovora.
/// </summary>
[ApiController]
[Route("api/lab03")]
[RequireAuth]
public sealed class Lab03PreviewController : ControllerBase
{
    private const int MaxChars = 2000;

    // ISPRAVLJENO: bez preusmjeravanja; spajanje samo na provjerene (javne) adrese.
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(3),
        ConnectCallback = ConnectToPublicAddressAsync,
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
        MaxResponseContentBufferSize = 1024 * 1024,
    };

    [HttpGet("preview")]
    public async Task<IActionResult> Preview([FromQuery] string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var target) ||
            (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
        {
            return BadRequest(new { error = "Dopušteni su samo http i https URL-ovi." });
        }

        // ISPRAVLJENO: provjera odredišta PRIJE slanja zahtjeva.
        IPAddress[] addresses;
        try
        {
            addresses = IPAddress.TryParse(target.DnsSafeHost, out var literal)
                ? new[] { literal }
                : await Dns.GetHostAddressesAsync(target.DnsSafeHost);
        }
        catch (SocketException)
        {
            return BadRequest(new { error = "Host nije moguće razriješiti." });
        }

        if (addresses.Length == 0 || addresses.Any(IsForbidden))
        {
            return BadRequest(new { error = "Odredište nije dopušteno." });
        }

        try
        {
            using var response = await Client.GetAsync(target);
            var body = await response.Content.ReadAsStringAsync();
            var content = body.Length > MaxChars ? body[..MaxChars] : body;
            return Ok(new { url, status = (int)response.StatusCode, content });
        }
        catch (Exception)
        {
            // Generička poruka – ne otkrivamo detalje interne mreže.
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "Dohvat nije uspio." });
        }
    }

    /// <summary>Je li adresa zabranjena (nije javna adresa na internetu)?</summary>
    public static bool IsForbidden(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] == 0                                   // 0.0.0.0/8
                || b[0] == 10                                  // 10.0.0.0/8
                || b[0] == 127                                 // 127.0.0.0/8
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)  // 100.64.0.0/10 (CGNAT)
                || (b[0] == 169 && b[1] == 254)                // 169.254.0.0/16 (link-local, cloud metadata)
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)   // 172.16.0.0/12
                || (b[0] == 192 && b[1] == 168)                // 192.168.0.0/16
                || b[0] >= 224;                                // multicast i rezervirano
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return address.IsIPv6LinkLocal      // fe80::/10
                || address.IsIPv6SiteLocal      // fec0::/10
                || address.IsIPv6Multicast      // ff00::/8
                || (b[0] & 0xFE) == 0xFC;       // fc00::/7 (unique local)
        }

        return true; // nepoznata obitelj adresa – odbij
    }

    /// <summary>Spajanje samo na javne adrese – provjera u trenutku spajanja (DNS rebinding).</summary>
    private static async ValueTask<Stream> ConnectToPublicAddressAsync(
        SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken);
        var allowed = addresses.FirstOrDefault(a => !IsForbidden(a))
                      ?? throw new HttpRequestException("Odredište nije dopušteno.");
        if (addresses.Any(IsForbidden))
        {
            throw new HttpRequestException("Odredište nije dopušteno.");
        }

        var socket = new Socket(allowed.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(allowed, context.DnsEndPoint.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab03"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab03"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab03]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab03` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab03*.
- **Rider:** *Unit Tests* → desni klik na `Lab03SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab03/Lab03SecurityTests.cs` i `Lab03FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Test `InternalDestinationsAreRejected` je *teorija* s četiri URL-a (127.0.0.1, localhost, [::1],
169.254.169.254) – svaki mora vratiti `400` bez tajne u tijelu.

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju i pošaljite zahtjeve **4)–7)**: svi vraćaju `400` (`"Odredište nije dopušteno."`).
Zahtjev **8)** (`ftp://`) vraća `400`, a **2)** (`https://example.com`) i dalje radi.

### c) Ponovno skeniranje

Ponovite Intruder/Fuzzer napad s portovima i varijantama zapisa adrese: `http://2130706433/`
(127.0.0.1 kao broj), `http://0x7f000001/`, `http://127.1/`, `http://[::ffff:127.0.0.1]/`. Razmislite zašto ih
popravak odbija (razrješavanje u `IPAddress` + `MapToIPv4`), a naivna provjera stringa ne bi.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte u konfiguraciju allowlistu domena (`Lab03:AllowedHosts`) i proširite popravak tako da
dopušta samo te domene. Napišite test koji provjerava da `https://example.com` prolazi provjeru, a
`https://evil.example` vraća `400` (bez stvarnog dohvata – testirajte validaciju).

**Pitanja za razmišljanje:**

1. Zašto provjera `if (url.Contains("localhost") || url.Contains("127.0.0.1"))` nije dovoljna? Navedite tri zaobilaženja.
2. Što je DNS rebinding i zašto provjera adrese *prije* `GetAsync` sama po sebi ne štiti od njega?
3. Koje mjere na razini infrastrukture (mreža, oblak) smanjuju štetu SSRF-a čak i ako aplikacija ima propust?
