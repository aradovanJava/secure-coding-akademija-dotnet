# Lab09 – Umetanje naredbi operacijskog sustava (OS command injection)

> **OWASP Top 10:2025:** A05 Injection · **CWE:** CWE-78 (Improper Neutralization of Special Elements used in
> an OS Command) · **Endpoint:** `GET /api/lab09/ping?host=` · **Zahtjevi:** `http/lab09.http`

## 1. Cilj vježbe

Dijagnostička funkcija "ping" pokreće naredbu ljuske (*shell*) u koju se umeće parametar `host`.
Pokrenut ćete proizvoljnu naredbu na poslužitelju (bezopasni `whoami`/`echo`), a zatim propust ukloniti
strogom validacijom i **izbjegavanjem ljuske** te ga testom zaključati.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab09/Lab09Controller.cs`, metoda `Ping` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab09/Lab09SecurityTests.cs`, `Lab09FunctionalTests.cs` |

## 3. Opis ranjivosti

Ljuska (`cmd.exe`, `sh`) ne izvršava samo jedan program – ona **interpretira** cijeli redak: `&`, `&&`, `|`,
`;`, `` ` ``, `$( )`, preusmjeravanja `>`… Ako je dio retka korisnički unos, korisnik dodaje vlastite naredbe,
koje se izvršavaju s ovlastima aplikacije (čitanje konfiguracije i tajni, instalacija zlonamjernog softvera,
napad na internu mrežu). Ovo je jedna od najtežih posljedica – izravno izvršavanje koda (RCE).

Primjeri: *Shellshock* (2014., Bash), brojni mrežni uređaji (usmjerivači, VPN koncentratori) s
dijagnostičkim "ping/traceroute" stranicama – točno ovaj obrazac.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju i otvorite `http/lab09.http`.

1. **1)** `?host=127.0.0.1` → `200` s izlazom naredbe `ping`.
2. **2)** `127.0.0.1 & whoami` (radi i u `cmd.exe` i u `sh`):

   ```http
   GET http://localhost:5080/api/lab09/ping?host=127.0.0.1%20%26%20whoami
   ```

   **Očekivani rezultat:** u polju `output` je, uz izlaz pinga, i ime korisničkog računa pod kojim radi
   aplikacija (npr. `racunalo\ana` ili `ana`) – dokaz izvršavanja proizvoljne naredbe.
3. **3)** Windows: `127.0.0.1 & type C:\Windows\win.ini` – sadržaj datoteke sustava.
4. **4)** Linux/macOS: `127.0.0.1; cat /etc/passwd`.
5. **5)** `127.0.0.1 & echo PWNED_LAB09` – bezopasni marker; isti payload koristi sigurnosni test.

curl (bash): `curl -s -G http://localhost:5080/api/lab09/ping --data-urlencode "host=127.0.0.1 & whoami"`
PowerShell: `curl.exe -s -G http://localhost:5080/api/lab09/ping --data-urlencode "host=127.0.0.1 & whoami"`

**ZAP:** *Active Scan* nad `GET /api/lab09/ping?host=127.0.0.1` → alarm *Remote OS Command Injection*.
**Burp Intruder:** pozicija na vrijednosti `host`, lista separatora (`&`, `&&`, `|`, `;`, `%0a`) + `echo PWNED`.

## 5. Analiza uzroka

```csharp
psi.FileName = "cmd.exe";  psi.Arguments = "/c ping -n 1 " + host;        // Windows
psi.FileName = "/bin/sh";  psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("ping -c 1 " + host);  // ostalo
```

Unos se spaja u **naredbeni redak koji interpretira ljuska**. Nema validacije – dopušteni su razmaci i
metaznakovi ljuske. (Čak i `ArgumentList` ovdje ne pomaže, jer je cijeli redak jedan argument `sh -c`.)

## 6. Popravak

- **Izbjegnite ljusku i vanjske programe** kad postoji API: `System.Net.NetworkInformation.Ping`.
- **Allowlista ulaza:** valjana IP adresa (`IPAddress.TryParse`) ili ime hosta (`^[A-Za-z0-9.-]{1,253}$`);
  sve ostalo → `400`. Allowlista (što je dopušteno) je pouzdanija od blockliste (koje znakove zabraniti).
- Ako vanjski program baš treba pokrenuti: izravno (`FileName = "ping"`), bez `cmd.exe /c` / `sh -c`, s
  argumentima u `ProcessStartInfo.ArgumentList` (svaki argument zasebno, bez interpretacije ljuske) – i
  dalje uz validaciju (npr. host koji počinje s `-` bio bi protumačen kao opcija programa).
- Aplikaciju pokrećite s najmanjim ovlastima (ne kao Administrator/root), u kontejneru bez nepotrebnih alata.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab09/Lab09Controller.cs` (grana `rjesenja`):

```csharp
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab09;

/// <summary>
/// Lab09 – A05 Injection: OS command injection (CWE-78).
///
/// ISPRAVLJENO:
///  - stroga validacija (allowlista): dopuštena je samo IP adresa ili ime hosta
///    (<c>^[A-Za-z0-9.-]{1,253}$</c>) – znakovi &amp;, ;, |, razmak, $ … se odbijaju s 400,
///  - nema ljuske: koristi se <see cref="Ping"/> iz .NET-a umjesto pokretanja vanjske naredbe.
///    (Ako vanjski program baš treba pokrenuti: <c>ProcessStartInfo.ArgumentList</c>, bez cmd.exe/sh.)
/// </summary>
[ApiController]
[Route("api/lab09")]
public sealed partial class Lab09Controller : ControllerBase
{
    [GeneratedRegex("^[A-Za-z0-9.-]{1,253}$")]
    private static partial Regex HostnamePattern();

    [HttpGet("ping")]
    public async Task<IActionResult> Ping([FromQuery] string? host)
    {
        // ISPRAVLJENO: allowlista dopuštenih znakova / valjana IP adresa.
        if (string.IsNullOrEmpty(host) || (!IPAddress.TryParse(host, out _) && !HostnamePattern().IsMatch(host)))
        {
            return BadRequest(new { error = "Neispravan host. Dopuštena je IP adresa ili ime hosta." });
        }

        try
        {
            // ISPRAVLJENO: bez ljuske – Ping API šalje ICMP zahtjev izravno.
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(host, 2000);
            return Ok(new
            {
                host,
                reachable = reply.Status == IPStatus.Success,
                status = reply.Status.ToString(),
                roundtripMs = reply.RoundtripTime,
            });
        }
        catch (PingException)
        {
            return Ok(new { host, reachable = false, status = "Neuspjeh" });
        }
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab09"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab09"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab09]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab09` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab09*.
- **Rider:** *Unit Tests* → desni klik na `Lab09SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab09/Lab09SecurityTests.cs` i `Lab09FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi: `127.0.0.1 & echo PWNED_LAB09` → `400` i tijelo bez `PWNED_LAB09`; `127.0.0.1;id` → `400`.
Funkcionalni test: `host=127.0.0.1` → `200` (bez obzira je li ping stvarno uspio).

### b) Ponovljeni napad

Zahtjevi 2)–5) vraćaju `400 {"error":"Neispravan host. Dopuštena je IP adresa ili ime hosta."}`.
Zahtjev 1) vraća npr. `{"host":"127.0.0.1","reachable":true,"status":"Success","roundtripMs":0}`, a 6)
(`host=localhost`) također radi.

### c) Ponovno skeniranje

Ponovite ZAP *Active Scan* i Burp Intruder s listom separatora – svi odgovori su `400`.
`semgrep scan --config p/csharp src/` više ne prijavljuje `Process.Start` s korisničkim unosom.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte endpoint `GET /api/lab09/lookup?host=` koji vraća IP adrese hosta pomoću
`Dns.GetHostAddressesAsync` (bez vanjskih programa) i testove: valjano ime → `200`, `example.com;id` → `400`,
`-oProxyCommand=x` → `400`.

**Pitanja za razmišljanje:**

1. Zašto sama zamjena `&` i `;` (blocklista) nije dovoljna? Navedite barem tri druga metaznaka ljuske.
2. Koja je razlika između *command injection* i *argument injection*? Štiti li `ArgumentList` od obje?
3. Kako bi pokretanje aplikacije s najmanjim ovlastima (ili u kontejneru) ograničilo štetu ovog napada?
