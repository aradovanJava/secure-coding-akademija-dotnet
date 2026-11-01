# Lab06 – Kriptografski propusti: lozinke i šifriranje podataka

> **OWASP Top 10:2025:** A04 Cryptographic Failures · **CWE:** CWE-916 (Use of Password Hash With
> Insufficient Computational Effort), CWE-327 (Broken or Risky Cryptographic Algorithm), CWE-321 (Use of
> Hard-coded Cryptographic Key), CWE-329 (Generation of Predictable IV) · **Endpointi:** `/api/lab06/register`,
> `/login`, `/customers/export`, `/cards`, `/cards/{id}/masked` · **Zahtjevi:** `http/lab06.http`

## 1. Cilj vježbe

Dva česta kriptografska propusta: **(A)** lozinke "hashirane" MD5-om bez soli i **(B)** brojevi kartica
šifrirani AES-om u načinu ECB s ključem zapisanim u izvornom kodu. Naučit ćete razbiti takvu zaštitu
alatima, zamijeniti je ispravnim rješenjima (PBKDF2 sa solju; AES-GCM s nasumičnim nonceom i ključem iz
konfiguracije) i testovima dokazati razliku.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler (oba dijela) | `src/VulnShop.Api/Labs/Lab06/Lab06Controller.cs` |
| Dio A – hash lozinke | `src/VulnShop.Api/Labs/Lab06/Lab06Passwords.cs` – `Hash`, `Verify` |
| Dio B – šifriranje | `src/VulnShop.Api/Labs/Lab06/CardCrypto.cs` – `Encrypt`, `Decrypt` |
| Seed kupaca | `src/VulnShop.Api/Common/DbInitializer.cs`, `SeedLab06` (ivan/123456, petra/password, luka/qwerty, maja/123456 – hashira se metodom `Lab06Passwords.Hash`) |
| Konfiguracija ključa (za popravak) | `src/VulnShop.Api/appsettings.json` – `Lab06:EncryptionKey` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab06/Lab06SecurityTests.cs`, `Lab06FunctionalTests.cs` |

## 3. Opis ranjivosti

**Dio A – lozinke.** Hash funkcije opće namjene (MD5, SHA-1, SHA-256) su **brze**: grafička kartica
računa milijarde MD5 hasheva u sekundi. Bez **soli** (nasumične vrijednosti po korisniku) ista lozinka uvijek
daje isti hash, pa napadač razbija sve korisnike s istom lozinkom odjednom i koristi gotove tablice
(*rainbow tables*, CrackStation). Za lozinke se koriste namjerno **spore** funkcije s **solju**: PBKDF2,
bcrypt, scrypt, Argon2. Primjer: LinkedIn 2012. – 6,5 (kasnije 117) milijuna nesoljenih SHA-1 hasheva,
većina razbijena u danima.

`GET /api/lab06/customers/export` u ovoj vježbi namjerno simulira **već procurjelu** bazu (dump iz sigurnosne
kopije, SQL injection …). Pitanje vježbe nije kako sakriti dump, nego koliko vrijedi zaštita lozinki kada dump procuri.

**Dio B – šifriranje.** AES je dobar algoritam, ali **način rada ECB** šifrira svaki blok od 16 B neovisno i
bez IV-a: isti otvoreni tekst → isti šifrat (poznata "ECB slika pingvina"). Napadač vidi koji korisnici imaju
istu karticu, može premještati blokove, a šifrat nema zaštitu integriteta. Uz to je **ključ hardkodiran**:
tko ima izvorni kod (repozitorij, stari zaposlenik, dekompajlirani DLL – ILSpy/dotPeek), ima i ključ.

## 4. Eksploatacija – korak po korak

### Dio A – razbijanje hasheva lozinki

1. **1)** `GET /api/lab06/customers/export` →

   ```json
   [{"username":"ivan","passwordHash":"e10adc3949ba59abbe56e057f20f883e"},
    {"username":"luka","passwordHash":"d8578edf8458ce06fbc5bb76a58c5ca4"},
    {"username":"maja","passwordHash":"e10adc3949ba59abbe56e057f20f883e"},
    {"username":"petra","passwordHash":"5f4dcc3b5aa765d61d8327deb882cf99"}]
   ```

   Opažanja: 32 heksadecimalna znaka = MD5; **ivan i maja imaju isti hash** → istu lozinku.
2. Hasheve spremite u `hashes.txt` (jedan po retku) i pokrenite hashcat s priloženim rječnikom:

   ```bash
   hashcat -m 0 -a 0 hashes.txt wordlists/top-100.txt
   hashcat -m 0 hashes.txt --show
   ```

   Rezultat za nekoliko milisekundi: `123456`, `qwerty`, `password`. Alternativa bez instalacije: zalijepite
   hasheve na <https://crackstation.net/> (samo ove, nastavne hasheve!).
3. Provjera: `POST /api/lab06/login` s `{"username":"maja","password":"123456"}` → `200`.

### Dio B – ECB i hardkodirani ključ

1. **6)** i **7)** – dvaput spremite istu karticu `4111111111111111`.
2. **8)** `GET /api/lab06/cards` → oba zapisa imaju **identičan** `ciphertext` (dokaz ECB-a / nedostatka IV-a).
3. Ključ `AkademijaKljuc16` pronađite u `CardCrypto.cs` (ili `semgrep scan --config p/secrets .`).
4. Dešifriranje u **CyberChefu**: recepti *From Base64* → *AES Decrypt* (Key: `AkademijaKljuc16`, tip *UTF8*;
   Mode: *ECB*; Input: *Raw*; Output: *Raw*) → `4111111111111111`.
   Ili openssl (bash):

   ```bash
   echo '<ciphertext iz koraka 8>' | base64 -d | \
     openssl enc -d -aes-128-ecb -K $(echo -n AkademijaKljuc16 | xxd -p) -nosalt
   ```

## 5. Analiza uzroka

```csharp
// Lab06Passwords.cs
Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(password)));   // brz hash, bez soli, bez iteracija

// CardCrypto.cs
private static readonly byte[] HardcodedKey = Encoding.UTF8.GetBytes("AkademijaKljuc16");   // ključ u kodu
aes.EncryptEcb(Encoding.UTF8.GetBytes(cardNumber), PaddingMode.PKCS7);                    // ECB: deterministički, bez integriteta
```

## 6. Popravak

**Dio A:**

- PBKDF2-HMAC-SHA256 (`Rfc2898DeriveBytes.Pbkdf2`) s **≥ 600 000 iteracija** (OWASP *Password Storage Cheat
  Sheet*) i **nasumičnom solju od 16 B** po lozinci; uz hash pohranite algoritam, broj iteracija i sol.
  Alternativa: `PasswordHasher<T>` iz ASP.NET Core Identityja (PBKDF2 + sol + verzioniranje formata).
- Provjera u konstantnom vremenu (`CryptographicOperations.FixedTimeEquals`).
- Seed se hashira novom metodom (to se događa automatski jer `DbInitializer` poziva `Lab06Passwords.Hash`).
- Postojeće MD5 hasheve u stvarnoj bazi migrirate pri sljedećoj uspješnoj prijavi (ili *hash-wrapping*: PBKDF2(MD5(lozinka))).

**Dio B:**

- **AES-GCM** (`AesGcm`) – autentificirano šifriranje; za svaki zapis **nasumični 12-bajtni nonce**; pohranite
  `nonce || šifrat || tag (16 B)`.
- 256-bitni **ključ iz konfiguracije** (`Lab06:EncryptionKey`), u produkciji iz varijable okoline
  `Lab06__EncryptionKey` ili iz KMS-a / Azure Key Vaulta / AWS KMS-a (idealno *envelope encryption*); nikad u kodu.
- Za kartice u praksi: PCI DSS, tokenizacija kod platnog procesora – najbolji podatak je onaj koji ne čuvate.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab06/Lab06Passwords.cs` (grana `rjesenja`):

```csharp
using System.Globalization;
using System.Security.Cryptography;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio A) – pohrana lozinki kupaca.
///
/// ISPRAVLJENO: PBKDF2-HMAC-SHA256 (<see cref="Rfc2898DeriveBytes.Pbkdf2(string, byte[], int, HashAlgorithmName, int)"/>)
/// s 600 000 iteracija (preporuka OWASP-a) i nasumičnom solju od 16 B za SVAKU lozinku.
/// Zapis: <c>pbkdf2-sha256$&lt;iteracije&gt;$&lt;sol Base64&gt;$&lt;hash Base64&gt;</c> – parametri su
/// pohranjeni uz hash pa se broj iteracija kasnije može povećati.
/// Alternativa: <c>PasswordHasher&lt;T&gt;</c> iz ASP.NET Core Identityja.
/// </summary>
public static class Lab06Passwords
{
    private const string Prefix = "pbkdf2-sha256";
    private const int Iterations = 600_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string storedHash)
    {
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations))
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        // Usporedba u konstantnom vremenu.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
```


Datoteka `src/VulnShop.Api/Labs/Lab06/CardCrypto.cs` (grana `rjesenja`):

```csharp
using System.Security.Cryptography;
using System.Text;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio B) – šifriranje brojeva kartica.
///
/// ISPRAVLJENO:
///  - AES-GCM (autentificirano šifriranje) s nasumičnim 12-bajtnim nonceom za SVAKI zapis,
///  - pohranjuje se nonce || šifrat || oznaka (tag, 16 B), kodirano Base64,
///  - 256-bitni ključ dolazi iz konfiguracije (<c>Lab06:EncryptionKey</c>) – u produkciji iz
///    varijable okoline <c>Lab06__EncryptionKey</c> ili iz KMS-a / Azure Key Vaulta, nikad iz koda.
/// </summary>
public sealed class CardCrypto
{
    private const int NonceSize = 12; // AesGcm.NonceByteSizes.MaxSize
    private const int TagSize = 16;   // AesGcm.TagByteSizes.MaxSize

    private readonly byte[] _key;

    public CardCrypto(IConfiguration configuration)
    {
        var base64Key = configuration["Lab06:EncryptionKey"]
            ?? throw new InvalidOperationException("Nedostaje konfiguracijski ključ Lab06:EncryptionKey.");
        _key = Convert.FromBase64String(base64Key);
        if (_key.Length != 32)
        {
            throw new InvalidOperationException("Lab06:EncryptionKey mora imati 32 bajta (256 bita).");
        }
    }

    /// <summary>Šifrira broj kartice; rezultat je Base64(nonce || šifrat || tag).</summary>
    public string Encrypt(string cardNumber)
    {
        var plaintext = Encoding.UTF8.GetBytes(cardNumber);
        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        var ciphertext = output.AsSpan(NonceSize, plaintext.Length);
        var tag = output.AsSpan(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return Convert.ToBase64String(output);
    }

    /// <summary>Dešifrira i provjerava integritet (izmijenjen šifrat → CryptographicException).</summary>
    public string Decrypt(string base64Ciphertext)
    {
        var input = Convert.FromBase64String(base64Ciphertext);
        var nonce = input.AsSpan(0, NonceSize);
        var ciphertext = input.AsSpan(NonceSize, input.Length - NonceSize - TagSize);
        var tag = input.AsSpan(input.Length - TagSize, TagSize);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
```


Datoteka `src/VulnShop.Api/Labs/Lab06/Lab06Controller.cs` (grana `rjesenja`):

```csharp
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 – A04 Cryptographic Failures (CWE-916, CWE-327, CWE-321, CWE-329).
///
/// Dio A: registracija i prijava kupaca i javni "export" koji simulira procurjelu bazu (dump) –
/// NAMJERNO bez autentikacije. ISPRAVLJENO u <see cref="Lab06Passwords"/> (PBKDF2 + sol).
///
/// Dio B: pohrana brojeva kartica. ISPRAVLJENO u <see cref="CardCrypto"/> (AES-GCM, nasumični
/// nonce, ključ iz konfiguracije).
/// </summary>
[ApiController]
[Route("api/lab06")]
public sealed class Lab06Controller(Db db, IConfiguration configuration) : ControllerBase
{
    // ISPRAVLJENO: ključ se čita iz konfiguracije (Lab06:EncryptionKey), ne iz izvornog koda.
    private readonly CardCrypto _crypto = new(configuration);

    public sealed record Credentials(string? Username, string? Password);

    public sealed record CardRequest(string? CardNumber);

    // ----------------------------- Dio A: lozinke -----------------------------

    [HttpPost("register")]
    public IActionResult Register([FromBody] Credentials request)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { error = "Nedostaje korisničko ime ili lozinka." });
        }

        var exists = Convert.ToInt64(db.Scalar(
            "SELECT COUNT(*) FROM lab06_customers WHERE username = $u", ("$u", request.Username)));
        if (exists > 0)
        {
            return Conflict(new { error = "Korisnik već postoji." });
        }

        db.Execute(
            "INSERT INTO lab06_customers (username, password_hash) VALUES ($u, $h)",
            ("$u", request.Username), ("$h", Lab06Passwords.Hash(request.Password)));
        return Ok(new { username = request.Username, status = "registriran" });
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] Credentials request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        var stored = db.Scalar(
            "SELECT password_hash FROM lab06_customers WHERE username = $u", ("$u", request.Username)) as string;
        if (stored is null || !Lab06Passwords.Verify(request.Password, stored))
        {
            return Unauthorized(new { error = "Neispravni podaci." });
        }

        return Ok(new { username = request.Username, status = "prijavljen" });
    }

    /// <summary>
    /// NAMJERNO bez autentikacije: simulira bazu lozinki koja je procurjela (npr. iz sigurnosne
    /// kopije). Pitanje vježbe nije "kako sakriti dump", nego "što napadač može s njim".
    /// </summary>
    [HttpGet("customers/export")]
    public IActionResult Export() =>
        Ok(db.Query("SELECT username, password_hash FROM lab06_customers ORDER BY username")
            .Select(r => new { username = r.GetString("username"), passwordHash = r.GetString("password_hash") }));

    // ----------------------------- Dio B: kartice -----------------------------

    [HttpPost("cards")]
    public IActionResult StoreCard([FromBody] CardRequest request)
    {
        var cardNumber = request.CardNumber?.Replace(" ", string.Empty);
        if (cardNumber is null || cardNumber.Length is < 12 or > 19 || !cardNumber.All(char.IsAsciiDigit))
        {
            return BadRequest(new { error = "Neispravan broj kartice." });
        }

        var ciphertext = _crypto.Encrypt(cardNumber);
        var id = db.Use(conn =>
        {
            using var insert = Db.CreateCommand(conn,
                "INSERT INTO lab06_cards (owner, ciphertext, last4) VALUES ('demo', $c, $l); SELECT last_insert_rowid();",
                ("$c", ciphertext), ("$l", cardNumber[^4..]));
            return Convert.ToInt64(insert.ExecuteScalar());
        });
        return Ok(new { id, ciphertext });
    }

    [HttpGet("cards")]
    public IActionResult ListCards() =>
        Ok(db.Query("SELECT id, ciphertext FROM lab06_cards ORDER BY id")
            .Select(r => new { id = r.GetInt64("id"), ciphertext = r.GetString("ciphertext") }));

    [HttpGet("cards/{id:long}/masked")]
    public IActionResult Masked(long id)
    {
        var last4 = db.Scalar("SELECT last4 FROM lab06_cards WHERE id = $id", ("$id", id)) as string;
        return last4 is null
            ? NotFound(new { error = "Kartica nije pronađena." })
            : Ok(new { id, masked = "**** **** **** " + last4 });
    }
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab06"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab06"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab06]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab06` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab06*.
- **Rider:** *Unit Tests* → desni klik na `Lab06SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab06/Lab06SecurityTests.cs` i `Lab06FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Dio A: dva korisnika s istom lozinkom → različiti hashevi; hash ≠ MD5 lozinke i nije 32 heks znaka; seed
kupci ivan i maja više nemaju isti hash. Dio B: isti broj kartice dvaput → različiti šifrati; šifrat dulji
od 16 + 12 B; ključ `AkademijaKljuc16` u ECB načinu više ne vraća broj kartice.

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju: export sada vraća hasheve oblika
`pbkdf2-sha256$600000$<sol>$<hash>`, različite za ivana i maju; hashcat `-m 0` ih ne prepoznaje kao MD5.
Dvije iste kartice imaju različite šifrate, a CyberChef/openssl s ključem `AkademijaKljuc16` u ECB načinu
ne daje broj kartice. Registracija i prijava rade (prijava je primjetno sporija – to je namjerno).

### c) Ponovno skeniranje

`semgrep scan --config p/secrets .` i SonarQube for IDE više ne prijavljuju hardkodirani ključ ni MD5/ECB u
`Lab06` (ključ u `appsettings.json` je razvojni – u stvarnom projektu ide u *User Secrets* / Key Vault).

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** napišite test koji provjerava da se šifrat ne može neprimjetno izmijeniti – promijenite jedan
bajt Base64 šifrata i pokažite da `CardCrypto.Decrypt` baca `CryptographicException` (integritet GCM-a).
Za `CardCrypto` u testu napravite konfiguraciju s `ConfigurationBuilder().AddInMemoryCollection(...)`.

**Pitanja za razmišljanje:**

1. Zašto je za lozinke **poželjno** da hash funkcija bude spora, a za provjeru integriteta datoteka nije?
2. Što se događa s AES-GCM-om ako se isti nonce ponovno upotrijebi s istim ključem? Zašto je to katastrofalno?
3. Kako biste rotirali ključ za šifriranje kartica bez gašenja aplikacije i bez gubitka starih podataka?
