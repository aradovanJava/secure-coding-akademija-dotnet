# Lab12 – Propusti u JSON Web Tokenima (JWT)

> **OWASP Top 10:2025:** A07 Authentication Failures · **CWE:** CWE-347 (Improper Verification of
> Cryptographic Signature), CWE-798 (Use of Hard-coded Credentials), CWE-613 (Insufficient Session
> Expiration) · **Endpointi:** `POST /api/lab12/login`, `GET /api/lab12/me`, `GET /api/lab12/admin` ·
> **Zahtjevi:** `http/lab12.http`

## 1. Cilj vježbe

Aplikacija izdaje JWT potpisan algoritmom HS256, ali ga provjerava ranjivo. Krivotvorit ćete
administratorski token na tri načina: `alg: none`, razbijanjem slabe tajne `secret123` i korištenjem
isteklog tokena. Popravak: allowlista algoritma, jaka tajna iz konfiguracije, usporedba potpisa u
konstantnom vremenu i obavezna provjera `exp` (i `iss`).

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| JWT (ručna implementacija) | `src/VulnShop.Api/Labs/Lab12/JwtService.cs` – `CreateToken(...)`, `Verify(token)`, klasa `Base64Url` |
| Kontroler | `src/VulnShop.Api/Labs/Lab12/Lab12Controller.cs` – `Login`, `Me`, `Admin` |
| Tajna za popravak | `src/VulnShop.Api/appsettings.json` – `Lab12:JwtSecret` (256 bita, Base64), `Lab12:Issuer` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab12/Lab12SecurityTests.cs`, `Lab12FunctionalTests.cs` |

`JwtService` ima javnu metodu `CreateToken(string username, string role, DateTimeOffset expiresAt)` kako bi
test mogao izraditi **istekli** token potpisan ispravnim ključem.

## 3. Opis ranjivosti

JWT ima tri dijela odvojena točkom: `zaglavlje.tijelo.potpis`, svaki kodiran Base64URL-om. Zaglavlje i tijelo
**nisu šifrirani** – svatko ih može pročitati (<https://jwt.io>). Sigurnost počiva isključivo na **provjeri
potpisa** na poslužitelju. Ranjivi `Verify`:

1. čita `alg` **iz samog tokena** i za `none` preskače provjeru potpisa (CVE-2015-9235 i slični u
   brojnim bibliotekama),
2. tajna `secret123` je kratka, hardkodirana i nalazi se u svakom rječniku – HS256 token se može razbijati
   *offline*, bez ijednog zahtjeva prema poslužitelju,
3. ne provjerava `exp` – ukradeni token vrijedi zauvijek,
4. uspoređuje potpis običnim `!=` (curenje informacija preko vremena usporedbe).

## 4. Eksploatacija – korak po korak

Otvorite `http/lab12.http`.

1. **1)** prijava `ana` / `Ana123!` → `{"token":"eyJhbGciOiJIUzI1NiIs...","tokenType":"Bearer"}`; token kopirajte u `@jwt`.
2. Zalijepite token na <https://jwt.io> (ili CyberChef → *JWT Decode*): tijelo je
   `{"sub":"ana","role":"USER","iat":...,"exp":...}`.
3. **2)** `/me` → `200`; **3)** `/admin` → `403`.

**Napad 1 – `alg: none`.** Izradite zaglavlje `{"alg":"none","typ":"JWT"}` i tijelo
`{"sub":"ana","role":"ADMIN","exp":4102444800}`, kodirajte ih Base64URL-om (CyberChef: *To Base64* s
abecedom *URL safe*, bez `=`) i spojite s **praznim potpisom** (token završava točkom). Gotov token je u
zahtjevu **4)** → `200 {"message":"Dobrodošli u administraciju, ana!"}`.

**Napad 2 – razbijanje slabe tajne.** Spremite Anin token u `token.txt` i pokrenite:

```bash
hashcat -m 16500 -a 0 token.txt wordlists/top-100.txt
hashcat -m 16500 token.txt --show        # ...:secret123
```

S poznatom tajnom potpišite vlastiti token s `"role":"ADMIN"` (jwt.io: upišite `secret123` u polje za tajnu;
ili CyberChef *JWT Sign*, algoritam HS256). Primjer gotovog tokena je u zahtjevu **5)** → `200`.
(Alternativa: alat *jwt_tool* – `python3 jwt_tool.py <token> -C -d wordlists/top-100.txt`.)

**Napad 3 – istekli token.** Zahtjev **6)** šalje token s `exp` = 1. 1. 2020. → `/me` vraća `200`.

**Burp:** ekstenzija *JWT Editor* (BApp Store) omogućuje izmjenu i ponovno potpisivanje tokena u Repeateru,
uključujući napad `alg: none`.

## 5. Analiza uzroka

```csharp
private static readonly byte[] Secret = Encoding.UTF8.GetBytes("secret123");       // slaba, hardkodirana tajna
var alg = header["alg"]?.GetValue<string>();
if (!string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase)) { ... }    // "none" preskače potpis
if (expected != parts[2]) return null;                                           // nije konstantno vrijeme
// RANJIVO: exp se ne provjerava.
```

Temeljna pogreška: poslužitelj dopušta da **token sam kaže kako ga treba provjeriti** (`alg`) i ne provodi
vlastita pravila (algoritam, rok valjanosti, izdavatelj).

## 6. Popravak

- **Allowlista algoritma:** prihvaća se isključivo `HS256` (ono što poslužitelj očekuje), nikad `none`.
- **Jaka tajna:** barem 256 nasumičnih bita, iz konfiguracije (`Lab12:JwtSecret`), u produkciji iz varijable
  okoline `Lab12__JwtSecret` ili Key Vaulta; nikad u kodu. Novu tajnu generirajte npr.
  `[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))` (PowerShell) ili
  `openssl rand -base64 32`.
- **Usporedba potpisa u konstantnom vremenu:** `CryptographicOperations.FixedTimeEquals`.
- **Obavezni `exp`** (i `iss`, po potrebi `aud`, `nbf`) – istekli token se odbija.
- U stvarnim projektima: provjerena biblioteka (`Microsoft.AspNetCore.Authentication.JwtBearer` /
  `Microsoft.IdentityModel.JsonWebTokens`) s `TokenValidationParameters` (`ValidAlgorithms`,
  `ValidateLifetime`, `ValidIssuer`…), kratko trajanje pristupnog tokena + *refresh token*, za više servisa
  asimetrični algoritmi (RS256/ES256).

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab12/JwtService.cs` (grana `rjesenja`):

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VulnShop.Api.Labs.Lab12;

/// <summary>
/// Lab12 – RUČNA implementacija JWT-a (HS256) BEZ vanjskih biblioteka: Base64URL + HMAC-SHA256.
///
/// ISPRAVLJENO:
///  - 256-bitna nasumična tajna iz konfiguracije (<c>Lab12:JwtSecret</c>, Base64) – u produkciji iz
///    varijable okoline <c>Lab12__JwtSecret</c> ili Key Vaulta; nikad u kodu,
///  - allowlista algoritma: prihvaća se ISKLJUČIVO <c>HS256</c> (<c>none</c> i sve ostalo → odbijeno),
///  - potpis se uspoređuje u konstantnom vremenu (<see cref="CryptographicOperations.FixedTimeEquals"/>),
///  - obavezni su <c>exp</c> (mora biti u budućnosti) i <c>iss</c> (mora odgovarati očekivanom izdavatelju).
/// U stvarnim projektima koristite provjerenu biblioteku (Microsoft.IdentityModel.JsonWebTokens,
/// <c>AddJwtBearer</c>) umjesto vlastite implementacije.
/// </summary>
public sealed class JwtService
{
    private readonly byte[] _secret;
    private readonly string _issuer;

    public JwtService(IConfiguration configuration)
    {
        var base64Secret = configuration["Lab12:JwtSecret"]
            ?? throw new InvalidOperationException("Nedostaje konfiguracijski ključ Lab12:JwtSecret.");
        _secret = Convert.FromBase64String(base64Secret);
        if (_secret.Length < 32)
        {
            throw new InvalidOperationException("Lab12:JwtSecret mora imati barem 256 bita (32 bajta).");
        }
        _issuer = configuration["Lab12:Issuer"] ?? "vulnshop-akademija";
    }

    /// <summary>Rezultat uspješne provjere tokena.</summary>
    public sealed record VerifiedToken(string Subject, string Role, long? ExpiresAt);

    /// <summary>Izrađuje token koji vrijedi 15 minuta.</summary>
    public string CreateToken(string username, string role) =>
        CreateToken(username, role, DateTimeOffset.UtcNow.AddMinutes(15));

    /// <summary>
    /// Izrađuje HS256 token s proizvoljnim vremenom isteka (javna metoda – testovi pomoću nje
    /// izrađuju istekli token potpisan ISPRAVNIM ključem).
    /// </summary>
    public string CreateToken(string username, string role, DateTimeOffset expiresAt)
    {
        var header = new JsonObject { ["alg"] = "HS256", ["typ"] = "JWT" };
        var payload = new JsonObject
        {
            ["iss"] = _issuer,
            ["sub"] = username,
            ["role"] = role,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        var signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." +
                           Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        return signingInput + "." + Base64Url.Encode(Sign(signingInput));
    }

    /// <summary>ISPRAVLJENA provjera tokena. Vraća <c>null</c> ako token nije prihvaćen.</summary>
    public VerifiedToken? Verify(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || parts[2].Length == 0)
            {
                return null;
            }

            // ISPRAVLJENO: algoritam NE bira klijent – prihvaćamo samo HS256.
            var header = JsonNode.Parse(Base64Url.Decode(parts[0]))!.AsObject();
            if (header["alg"]?.GetValue<string>() != "HS256")
            {
                return null;
            }

            // ISPRAVLJENO: usporedba potpisa u konstantnom vremenu.
            var expected = Sign(parts[0] + "." + parts[1]);
            if (!CryptographicOperations.FixedTimeEquals(expected, Base64Url.Decode(parts[2])))
            {
                return null;
            }

            // ISPRAVLJENO: exp je obavezan i mora biti u budućnosti; iss mora odgovarati.
            var payload = JsonNode.Parse(Base64Url.Decode(parts[1]))!.AsObject();
            var exp = payload["exp"]?.GetValue<long>();
            if (exp is null || DateTimeOffset.FromUnixTimeSeconds(exp.Value) <= DateTimeOffset.UtcNow)
            {
                return null;
            }
            if (payload["iss"]?.GetValue<string>() != _issuer)
            {
                return null;
            }

            return new VerifiedToken(
                payload["sub"]?.GetValue<string>() ?? string.Empty,
                payload["role"]?.GetValue<string>() ?? string.Empty,
                exp);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private byte[] Sign(string signingInput) =>
        HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(signingInput));
}

/// <summary>Base64URL kodiranje (RFC 4648 §5) bez znakova za dopunu (=).</summary>
public static class Base64Url
{
    public static string Encode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        s = (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            _ => s,
        };
        return Convert.FromBase64String(s);
    }
}
```


`Lab12Controller.cs` se ne mijenja – sva provjera je u `JwtService`, koji se u `Program.cs` registrira kao
singleton (`AddSingleton<JwtService>()`); DI sam predaje `IConfiguration` konstruktoru.
</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab12"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab12"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab12]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab12` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab12*.
- **Rider:** *Unit Tests* → desni klik na `Lab12SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab12/Lab12SecurityTests.cs` i `Lab12FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi: token s `alg: none` i ulogom ADMIN → `401`; token potpisan s `secret123` → `401`; istekli token
izrađen kroz `JwtService.CreateToken(..., DateTimeOffset.UtcNow.AddMinutes(-5))` → `401`.

### b) Ponovljeni napad

Zahtjevi 4), 5) i 6) vraćaju `401`. Prijava i `/me` rade; novi token u tijelu ima i `"iss":"vulnshop-akademija"`.
hashcat s `top-100.txt` više ne pronalazi tajnu (256-bitna nasumična tajna nije u rječniku).

### c) Ponovno skeniranje

U Burpu (*JWT Editor*) ponovite napade `alg: none` i ponovno potpisivanje – svi vraćaju `401`.
`semgrep scan --config p/secrets .` više ne prijavljuje tajnu u `JwtService.cs`.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** napišite dva dodatna sigurnosna testa: (1) token s ispravnim potpisom, ali izmijenjenim tijelom
(promijenjena uloga u `ADMIN`, stari potpis) → `401`; (2) token s ispravnim potpisom i krivim `iss` → `401`
(za izradu takvog tokena u testu iskoristite tajnu iz `IConfiguration` dohvaćene preko `factory.Services`).

**Pitanja za razmišljanje:**

1. Što je napad *algorithm confusion* (RS256 → HS256) i zašto ga allowlista algoritma sprječava?
2. Kako opozvati (*revoke*) JWT prije isteka? Koje su prednosti i nedostaci *stateless* tokena?
3. Smije li JWT sadržavati osobne podatke (OIB, adresu)? Zašto?
