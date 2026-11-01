# Lab02 – Mass assignment i eskalacija privilegija

> **OWASP Top 10:2025:** A01 Broken Access Control · **CWE:** CWE-915 (Improperly Controlled Modification of
> Dynamically-Determined Object Attributes), CWE-269 (Improper Privilege Management) ·
> **Endpointi:** `GET/PUT /api/lab02/profile`, `GET /api/lab02/admin/users` · **Zahtjevi:** `http/lab02.http`

## 1. Cilj vježbe

Korisnik mijenja svoj profil (ime, e-pošta), ali uz dopuštena polja pošalje i `"role": "ADMIN"` – i postaje
administrator. Naučit ćete zašto se entiteti ne smiju vezati (*bindati*) izravno iz zahtjeva i kako to
spriječiti ulaznim DTO-om s allowlistom polja i validacijom.

## 2. Gdje je kod

| Što | Gdje |
|---|---|
| Kontroler | `src/VulnShop.Api/Labs/Lab02/Lab02ProfileController.cs` – `UpdateProfile`, `AdminUsers` |
| Ulazni model | ugniježđena klasa `ProfileEntity` (`DisplayName`, `Email`, **`Role`**) |
| Podaci | tablica `lab02_profiles` (user_id, display_name, email, role) – seed u `DbInitializer.SeedLab02` |
| Testovi | `tests/VulnShop.Tests/Labs/Lab02/Lab02SecurityTests.cs` (korisnik marko), `Lab02FunctionalTests.cs` (ana, admin) |

## 3. Opis ranjivosti

*Mass assignment* (u Railsu *mass assignment*, u Springu *autobinding*, u .NET-u *overposting*) nastaje kada
okvir automatski prepiše **sva** polja iz zahtjeva u objekt koji se potom sprema. Ako taj objekt sadrži
osjetljiva polja (uloga, stanje računa, `isVerified`, vlasnik), napadač ih jednostavno doda u JSON.

Poznati primjer: 2012. je Egor Homakov iskoristio mass assignment na GitHubu (Rails) i dodao svoj javni
ključ u repozitorij projekta Rails – bez ikakvih ovlasti. OWASP API Security Top 10 ovu klasu propusta
navodi kao *Broken Object Property Level Authorization* (API3:2023).

## 4. Eksploatacija – korak po korak

1. Pokrenite aplikaciju i otvorite `http/lab02.http`.
2. **1)** prijava kao `marko` / `Marko123!` → token u `@token`.
3. **2)** `GET /api/lab02/profile` → `"role": "USER"`.
4. **3)** `GET /api/lab02/admin/users` → `403 Forbidden` (očekivano).
5. **4)** napad – PUT s dodatnim poljem:

   ```http
   PUT http://localhost:5080/api/lab02/profile
   Authorization: Bearer <markov token>
   Content-Type: application/json

   {"displayName": "Marko", "email": "m@x.hr", "role": "ADMIN"}
   ```

   Odgovor: `200 OK` s `"role": "ADMIN"`.
6. **5)** ponovno `GET /api/lab02/admin/users` → **`200 OK` s popisom svih korisnika i njihovih e-adresa**
   (dokaz eskalacije privilegija).

curl (bash):

```bash
curl -s -X PUT http://localhost:5080/api/lab02/profile -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"displayName":"Marko","email":"m@x.hr","role":"ADMIN"}'
curl -s http://localhost:5080/api/lab02/admin/users -H "Authorization: Bearer $TOKEN"
```

**Burp Repeater:** uhvatite legitiman PUT (bez `role`), u Repeateru dodajte `"role":"ADMIN"` i pošaljite.
Kako napadač uopće zna za polje `role`? Vidi ga u odgovoru `GET /profile` – API sam otkriva model.

## 5. Analiza uzroka

```csharp
public sealed class ProfileEntity { public string? DisplayName ...; public string? Email ...; public string? Role ...; }

public IActionResult UpdateProfile([FromBody] ProfileEntity profile)
...
"UPDATE lab02_profiles SET ..., role = COALESCE($r, role) WHERE user_id = $id", ... ("$r", profile.Role) ...
```

Isti model služi za **izlaz** (prikaz profila) i **ulaz** (izmjenu). Model binder popuni svako svojstvo
koje postoji u JSON-u, a SQL naredba upisuje i `role`. Provjera ovlasti u `AdminUsers` je ispravna sama po
sebi – ali čita ulogu koju je napadač upravo sam postavio.

## 6. Popravak

- Ulazni **DTO** (*Data Transfer Object*) samo s poljima koja korisnik smije mijenjati (`DisplayName`, `Email`) – allowlista.
- Validacija ulaza (DataAnnotations: `[Required]`, `[StringLength]`, `[EmailAddress]`); `[ApiController]`
  automatski vraća `400` za neispravan model.
- SQL naredba ažurira **samo** dopuštene stupce.
- Uloga se mijenja isključivo kroz zaseban administratorski proces (poseban endpoint dostupan samo ADMIN-u, s revizijskim zapisom).
- Alternative: `[Bind("DisplayName,Email")]` (MVC), ručno mapiranje; za izlaz zaseban *response* DTO.

<details>
<summary>Referentno rješenje</summary>

Datoteka `src/VulnShop.Api/Labs/Lab02/Lab02ProfileController.cs` (grana `rjesenja`):

```csharp
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab02;

/// <summary>
/// Lab02 – A01 Broken Access Control: mass assignment / eskalacija privilegija (CWE-915, CWE-269).
///
/// ISPRAVLJENO: <c>PUT /api/lab02/profile</c> prima zaseban DTO (<see cref="ProfileUpdateRequest"/>)
/// koji sadrži SAMO polja koja korisnik smije mijenjati (displayName, email), uz validaciju
/// (DataAnnotations). Polje <c>role</c> iz JSON-a se ignorira – uloga se mijenja isključivo
/// kroz administratorski proces.
/// </summary>
[ApiController]
[Route("api/lab02")]
[RequireAuth]
public sealed class Lab02ProfileController(Db db) : ControllerBase
{
    /// <summary>ISPRAVLJENO: ulazni DTO bez polja Role (allowlista dopuštenih polja).</summary>
    public sealed class ProfileUpdateRequest
    {
        [Required, StringLength(100, MinimumLength = 1)]
        public string? DisplayName { get; set; }

        [Required, EmailAddress, StringLength(200)]
        public string? Email { get; set; }
    }

    [HttpGet("profile")]
    public IActionResult GetProfile() => Ok(LoadProfile(HttpContext.RequireCurrentUser().Id));

    [HttpPut("profile")]
    public IActionResult UpdateProfile([FromBody] ProfileUpdateRequest request)
    {
        // [ApiController] automatski vraća 400 ako validacija (DataAnnotations) ne prođe.
        var user = HttpContext.RequireCurrentUser();

        // ISPRAVLJENO: ažuriraju se samo dopuštena polja; stupac role se NE dira.
        db.Execute(
            "UPDATE lab02_profiles SET display_name = $d, email = $e WHERE user_id = $id",
            ("$d", request.DisplayName), ("$e", request.Email), ("$id", user.Id));

        return Ok(LoadProfile(user.Id));
    }

    [HttpGet("admin/users")]
    public IActionResult AdminUsers()
    {
        var user = HttpContext.RequireCurrentUser();

        var role = db.Scalar("SELECT role FROM lab02_profiles WHERE user_id = $id", ("$id", user.Id)) as string;
        if (role != "ADMIN")
        {
            return StatusCode(StatusCodes.Status403Forbidden,
                new { error = "Samo administrator smije vidjeti popis korisnika." });
        }

        var users = db.Query("SELECT user_id, display_name, email, role FROM lab02_profiles ORDER BY user_id")
            .Select(ToDto);
        return Ok(users);
    }

    private object LoadProfile(long userId) =>
        ToDto(db.Query(
            "SELECT user_id, display_name, email, role FROM lab02_profiles WHERE user_id = $id",
            ("$id", userId))[0]);

    private static object ToDto(Dictionary<string, object?> row) => new
    {
        userId = row.GetInt64("user_id"),
        displayName = row.GetString("display_name"),
        email = row.GetString("email"),
        role = row.GetString("role"),
    };
}
```

</details>

## 7. Provjera popravka

### a) Sigurnosni testovi

**Naredbeni redak** (u korijenu repozitorija):

```bash
dotnet test --filter "Category=Security&Lab=Lab02"   # prije popravka: crveno, nakon popravka: zeleno
dotnet test --filter "Lab=Lab02"                     # sigurnosni + funkcionalni testovi vježbe
```

**IDE:**

- **Visual Studio 2026:** *Test → Test Explorer* → *Group By → Traits* → desni klik na grupu **Lab [Lab02]** → *Run*.
- **VS Code:** panel *Testing* → `VulnShop.Tests.Labs.Lab02` → *Run Test*, ili *Terminal → Run Task… → test: jedna vježba → Lab02*.
- **Rider:** *Unit Tests* → desni klik na `Lab02SecurityTests` → *Run Unit Tests*.

Testovi se nalaze u `tests/VulnShop.Tests/Labs/Lab02/Lab02SecurityTests.cs` i `Lab02FunctionalTests.cs`.
Svi testovi vježbe moraju biti zeleni – i sigurnosni (ranjivost je otklonjena) i funkcionalni
(popravak nije pokvario normalan rad).

Testovi koriste korisnika `marko`: nakon PUT-a s `role=ADMIN` profil mora i dalje imati `USER`, a
`admin/users` vraća `403`.

### b) Ponovljeni napad

Ponovno pokrenite aplikaciju (baza se vraća na početno stanje) i ponovite korake 4)–6): PUT vraća `200`,
ali s `"role": "USER"`, a `admin/users` vraća `403`. Zahtjev **7)** (neispravna e-pošta) vraća `400` s
opisom greške validacije.

### c) Ponovno skeniranje

Burp Repeater: ponovite zahtjev s `"role":"ADMIN"` i varijantama (`"Role"`, `"ROLE"`) – nijedna ne mijenja ulogu.

## 8. Zadatak za samostalni rad i pitanja

**Zadatak:** dodajte endpoint `PUT /api/lab02/admin/users/{id}/role` dostupan samo administratoru (uloga se
provjerava iz tablice `users`, ne iz profila) i test koji dokazuje da marko na njega dobiva `403`, a admin `200`.

**Pitanja za razmišljanje:**

1. Zašto je allowlista polja (DTO) sigurnija od blockliste (`[JsonIgnore]` na `Role`)?
2. Koja još polja u tipičnoj web trgovini ne bi smjela biti izmjenjiva kroz korisnički profil?
3. Je li u redu da `GET /profile` vraća ulogu korisnika? Što bi se promijenilo da je ne vraća?
