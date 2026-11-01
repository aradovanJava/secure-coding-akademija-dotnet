# 00 – Postavljanje razvojnog okruženja (.NET 10)

Ova uputa vodi vas korak po korak od praznog računala do pokrenute aplikacije VulnShop Akademija
i prvih (namjerno) palih sigurnosnih testova. Odaberite **jedno** razvojno okruženje:

- [A. Visual Studio 2026](#a-visual-studio-2026) (Windows) – najjednostavnije za početnike na Windowsima
- [B. Visual Studio Code + C# Dev Kit](#b-visual-studio-code--c-dev-kit) (Windows, macOS, Linux)
- [C. JetBrains Rider](#c-jetbrains-rider) (Windows, macOS, Linux)
- [D. Samo naredbeni redak](#d-naredbeni-redak-cli) (bilo koji OS)

Na kraju su [rad s `.http` datotekama](#rad-s-http-datotekama), [napomene za PowerShell](#napomena-za-powershell)
i [rješavanje čestih problema](#rješavanje-čestih-problema).

---

## 0. Zajednički preduvjeti

### 0.1 .NET 10 SDK

1. Otvorite <https://dotnet.microsoft.com/download/dotnet/10.0> i preuzmite **SDK** (ne samo *Runtime*)
   za svoj operacijski sustav (Windows x64 / Arm64, macOS, Linux).
   - Windows (alternativa): `winget install Microsoft.DotNet.SDK.10`
   - macOS (alternativa): `brew install --cask dotnet-sdk`
   - Ubuntu: `sudo apt-get update && sudo apt-get install -y dotnet-sdk-10.0`
2. Otvorite **novi** terminal i provjerite instalaciju:

   ```bash
   dotnet --version        # mora ispisati 10.0.1xx ili noviji 10.0.x
   dotnet --list-sdks
   ```

Datoteka `global.json` u korijenu repozitorija traži SDK `10.0.100` uz `rollForward: latestFeature`, što znači
da prihvaća bilo koji SDK 10.0.1xx, 10.0.2xx … (ali ne 9.x ni 11.x).

> Visual Studio 2026 instalira .NET 10 SDK automatski uz radno opterećenje *ASP.NET and web development*.

### 0.2 Git

- Windows: <https://git-scm.com/download/win> (ili `winget install Git.Git`)
- macOS: `xcode-select --install` ili `brew install git`
- Linux: `sudo apt-get install -y git`

Provjera: `git --version`.

### 0.3 Kloniranje repozitorija (ako ne klonirate iz IDE-a)

```bash
git clone https://github.com/aradovanJava/secure-coding-akademija-dotnet.git
cd secure-coding-akademija-dotnet
```

---

## A. Visual Studio 2026

### A.1 Instalacija

1. Preuzmite **Visual Studio 2026 Community** (besplatno) s <https://visualstudio.microsoft.com/>.
2. U *Visual Studio Installeru* označite radno opterećenje (*workload*) **ASP.NET and web development**
   (uključuje .NET 10 SDK i podršku za `.http` datoteke). Kliknite **Install**.

### A.2 Kloniranje i otvaranje rješenja

1. Pokrenite Visual Studio → na početnom zaslonu odaberite **Clone a repository**.
2. U polje *Repository location* upišite `https://github.com/aradovanJava/secure-coding-akademija-dotnet.git`,
   odaberite lokalnu mapu (*Path*) i kliknite **Clone**.
3. Ako se rješenje ne otvori samo: **File → Open → Project/Solution…** i odaberite `SecureCodingAkademija.sln`.
4. U **Solution Exploreru** (View → Solution Explorer) vidjet ćete mape `src` (projekt `VulnShop.Api`) i
   `tests` (projekt `VulnShop.Tests`). Visual Studio sam vraća NuGet pakete (*restore*) – pričekajte da
   statusna traka javi *Ready*.
5. **Build → Build Solution** (Ctrl+Shift+B). U prozoru *Error List* pojavit će se **upozorenje NU1903** za
   `Newtonsoft.Json 12.0.3` – to je očekivano (namjerno ranjiv paket, vježba Lab05) i ne sprječava build.

### A.3 Pokretanje aplikacije

1. U alatnoj traci, u padajućem izborniku pokretanja (pokraj zelene strelice) odaberite projekt
   **VulnShop.Api** i profil **http**.
2. Pritisnite **F5** (s debuggerom) ili **Ctrl+F5** (bez debuggera).
3. Otvorit će se konzola s porukom `Now listening on: http://localhost:5080`.
4. Provjera u pregledniku: <http://localhost:5080/health> mora prikazati `Healthy`.

Za vježbu Lab04 postoji i profil **http-production** (isti port, `ASPNETCORE_ENVIRONMENT=Production`).

### A.4 Pokretanje testova (Test Explorer)

1. **Test → Test Explorer** (Ctrl+E, T).
2. Kliknite **Run All Tests** (ili desni klik na projekt `VulnShop.Tests` → *Run*).
3. Grupiranje po vježbama: u Test Exploreru kliknite ikonu **Group By** (ikona s hijerarhijom) i odaberite
   **Traits**. Testovi će se grupirati po `Category` (Functional / Security) i `Lab` (Lab01 … Lab15).
4. Pokretanje samo jedne vježbe: u grupi **Lab [Lab01]** desni klik → **Run**.
5. Filtriranje: u tražilicu Test Explorera upišite npr. `Trait:"Lab01"` ili `Trait:"Security"`.
6. Na grani `main` sigurnosni testovi su **crveni** – to je dokaz ranjivosti. Klikom na test u donjem
   dijelu prozora vidite poruku (npr. *Assert.Equal() Failure: Expected: NotFound, Actual: OK*).
7. Debugiranje testa: desni klik na test → **Debug** (prije toga postavite točku prekida, F9, u kodu vježbe).

### A.5 `.http` datoteke

1. U Solution Exploreru otvorite mapu rješenja ili dodajte postojeće datoteke: desni klik na rješenje →
   **Add → Existing Item…** → odaberite datoteke iz mape `http`. (Ili ih otvorite izravno: **File → Open → File…**.)
2. Iznad svakog zahtjeva pojavljuje se poveznica **Send request** (zeleni trokutić) – klikom šaljete zahtjev,
   a odgovor se prikazuje u desnom panelu.
3. Varijable (`@host`, `@token`) definirane su na vrhu datoteke. Token iz odgovora prijave ručno
   kopirajte u redak `@token = ...` (vidi [Rad s `.http` datotekama](#rad-s-http-datotekama)).

---

## B. Visual Studio Code + C# Dev Kit

### B.1 Instalacija

1. Instalirajte VS Code s <https://code.visualstudio.com/> i .NET 10 SDK (korak 0.1).
2. Otvorite VS Code → **Extensions** (Ctrl+Shift+X) i instalirajte:
   - **C# Dev Kit** (Microsoft) – automatski instalira i ekstenziju **C#**,
   - **REST Client** (Huachao Mao) – za `.http` datoteke.

   Nakon otvaranja repozitorija VS Code će te ekstenzije i sam preporučiti (`.vscode/extensions.json`).
3. C# Dev Kit može tražiti prijavu Microsoft računom – za osobnu i edukacijsku upotrebu je besplatan.

### B.2 Kloniranje i otvaranje

1. **Ctrl+Shift+P** → upišite **Git: Clone** → zalijepite
   `https://github.com/aradovanJava/secure-coding-akademija-dotnet.git` → odaberite mapu → **Open**.
2. Na pitanje *Do you trust the authors…* odgovorite **Yes, I trust the authors**.
3. U bočnoj traci **Explorer** pojavljuje se panel **Solution Explorer** (C# Dev Kit) s projektima
   `VulnShop.Api` i `VulnShop.Tests` (`.vscode/settings.json` već upućuje na `SecureCodingAkademija.sln`).
4. Build: **Ctrl+Shift+B** (zadatak *build*) ili u terminalu `dotnet build`.

### B.3 Pokretanje aplikacije

- **Run and Debug** (Ctrl+Shift+D) → odaberite **VulnShop.Api (http://localhost:5080)** → **F5**.
  (Konfiguracije su u `.vscode/launch.json`; postoji i *Production način (Lab04)*.)
- Ili u terminalu (**Terminal → New Terminal**):

  ```bash
  dotnet run --project src/VulnShop.Api --launch-profile http
  ```

- Ili **Terminal → Run Task… → run (http://localhost:5080)**.

### B.4 Pokretanje testova (Testing panel)

1. Otvorite panel **Testing** (ikona tikvice u bočnoj traci). C# Dev Kit automatski pronalazi xUnit testove.
2. **Run Tests** (dvostruka strelica) pokreće sve testove; strelica pokraj klase ili metode pokreće samo nju.
3. Testovi su organizirani po namespaceu: `VulnShop.Tests.Labs.Lab01` → `Lab01SecurityTests`,
   `Lab01FunctionalTests`.
4. Pokretanje po kategoriji ili vježbi preko zadataka: **Terminal → Run Task…** →
   *test: sigurnosni*, *test: funkcionalni* ili *test: jedna vježba* (nudi izbor Lab01 … Lab15).
5. Ili u terminalu: `dotnet test --filter "Lab=Lab01"`.

### B.5 `.http` datoteke (REST Client)

Otvorite npr. `http/lab01.http`. Iznad svakog zahtjeva pojavljuje se poveznica **Send Request**
(ili Ctrl+Alt+R kada je kursor u zahtjevu). Odgovor se otvara u novoj kartici desno.

---

## C. JetBrains Rider

1. Instalirajte Rider s <https://www.jetbrains.com/rider/> (besplatan za nekomercijalnu upotrebu /
   studentska licenca) i .NET 10 SDK.
2. Početni zaslon → **Get from VCS** (ili **File → Open → Get from Version Control…**) → URL
   `https://github.com/aradovanJava/secure-coding-akademija-dotnet.git` → **Clone**.
   Rider otvara `SecureCodingAkademija.sln` i vraća pakete.
3. Pokretanje: u gornjem desnom kutu odaberite konfiguraciju **VulnShop.Api: http** → **Run** (Shift+F10)
   ili **Debug** (Shift+F9). Rider čita profile iz `launchSettings.json`.
4. Testovi: **View → Tool Windows → Unit Tests** → **Run All**. Grupiranje: ikona **Group By** →
   **Categories** (Rider prikazuje xUnit `Trait` vrijednosti kao kategorije). Pokretanje jedne vježbe:
   desni klik na klasu `Lab01SecurityTests` → **Run Unit Tests**.
5. `.http` datoteke: Rider ima ugrađeni HTTP Client – otvorite `http/lab01.http` i kliknite zeleni trokutić
   pokraj zahtjeva.

---

## D. Naredbeni redak (CLI)

```bash
# u korijenu repozitorija
dotnet restore
dotnet build

# pokretanje aplikacije (Ctrl+C za zaustavljanje)
dotnet run --project src/VulnShop.Api --launch-profile http
dotnet run --project src/VulnShop.Api --launch-profile http-production   # Lab04

# testovi
dotnet test                                              # svi
dotnet test --filter "Category=Functional"               # funkcionalni (moraju proći)
dotnet test --filter "Category=Security"                 # sigurnosni (na main padaju)
dotnet test --filter "Lab=Lab07"                         # jedna vježba
dotnet test --filter "Category=Security&Lab=Lab07"       # sigurnosni testovi jedne vježbe
dotnet test --filter "FullyQualifiedName~Lab07SecurityTests.UnionSelectDoesNotLeakAccounts"   # jedan test
dotnet test --filter "Lab=Lab07" --logger "console;verbosity=detailed"                         # detaljan ispis
```

Testovi **ne trebaju** pokrenutu aplikaciju – svaki test pokreće aplikaciju u memoriji
(`WebApplicationFactory<Program>`) sa svježom bazom.

---

## Rad s `.http` datotekama

Mapa `http/` sadrži datoteku za svaku vježbu. Format radi u Visual Studiju 2026, VS Code (REST Client)
i Rideru:

```http
@host = http://localhost:5080
@token = ZALIJEPITE_TOKEN_OVDJE

### 1) Prijava kao ana (kopirajte "token" u @token)
POST {{host}}/api/auth/login
Content-Type: application/json

{"username": "ana", "password": "Ana123!"}

### 2) Zahtjev s tokenom
GET {{host}}/api/lab01/orders/1001
Authorization: Bearer {{token}}
```

1. Pokrenite aplikaciju (profil `http`, port 5080).
2. Pošaljite zahtjev za prijavu.
3. Iz odgovora kopirajte vrijednost `token` (bez navodnika) i zamijenite `ZALIJEPITE_TOKEN_OVDJE`.
   Spremite datoteku (Ctrl+S).
4. Šaljite ostale zahtjeve. `###` odvaja zahtjeve; redak koji počinje s `#` je komentar.

Token vrijedi dok se aplikacija ne ponovno pokrene (tokeni se čuvaju u memoriji).

## Napomena za PowerShell

U Windows PowerShellu je `curl` **alias** za `Invoke-WebRequest`, koji ima drukčije parametre. Koristite
`curl.exe` (dolazi uz Windows 10/11) ili `Invoke-RestMethod`:

```powershell
# curl.exe – isti parametri kao na Linuxu (pazite na navodnike u JSON-u)
curl.exe -s http://localhost:5080/health
curl.exe -s -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" `
  -d '{\"username\":\"ana\",\"password\":\"Ana123!\"}'

# Invoke-RestMethod – prijava i spremanje tokena u varijablu
$login = Invoke-RestMethod -Method Post -Uri http://localhost:5080/api/auth/login `
  -ContentType 'application/json' -Body '{"username":"ana","password":"Ana123!"}'
$token = $login.token
Invoke-RestMethod -Uri http://localhost:5080/api/lab01/orders/1003 -Headers @{ Authorization = "Bearer $token" }
```

U bashu (Linux, macOS, Git Bash):

```bash
TOKEN=$(curl -s -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" \
  -d '{"username":"ana","password":"Ana123!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s http://localhost:5080/api/lab01/orders/1003 -H "Authorization: Bearer $TOKEN"
```

## Rješavanje čestih problema

| Problem | Uzrok | Rješenje |
|---|---|---|
| `A compatible .NET SDK was not found` / `Requested SDK version: 10.0.100` | nije instaliran .NET 10 SDK (ili samo Runtime) | instalirajte **SDK** 10.0.x (korak 0.1), otvorite novi terminal; `dotnet --list-sdks` |
| `Failed to bind to address http://127.0.0.1:5080: address already in use` | port 5080 zauzet (npr. aplikacija već radi u drugom prozoru) | zatvorite drugu instancu. Windows: `netstat -ano \| findstr :5080` pa `taskkill /PID <pid> /F`; Linux/macOS: `lsof -i :5080` pa `kill <pid>`. Privremeno drugi port: `dotnet run --project src/VulnShop.Api --launch-profile http -- --urls http://localhost:5081` (i promijenite `@host`) |
| `NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json` | nema interneta ili korporativni proxy | provjerite vezu; za proxy postavite varijable `HTTP_PROXY` / `HTTPS_PROXY` ili `nuget.config` s `<config><add key="http_proxy" value="http://proxy:port" /></config>` |
| upozorenje `NU1903: Package 'Newtonsoft.Json' 12.0.3 has a known high severity vulnerability` | namjerno ranjiv paket (Lab05) | očekivano na grani `main`; nestaje nakon popravka Lab05 |
| testovi se ne pojavljuju u Test Exploreru | projekt nije buildan ili restore nije završio | **Build → Rebuild Solution**, zatim u Test Exploreru **Refresh**; u VS Codeu: *Ctrl+Shift+P → .NET: Clean* pa build |
| `.http` zahtjev vraća 401 | token nije kopiran, istekao je ili je aplikacija ponovno pokrenuta | ponovno pošaljite prijavu i kopirajte novi token u `@token` |
| u PowerShellu `curl` javlja grešku o parametru `-H` | `curl` je alias za `Invoke-WebRequest` | koristite `curl.exe` |
| VS Code: *The .NET Core SDK cannot be located* | VS Code je pokrenut prije instalacije SDK-a | potpuno zatvorite i ponovno pokrenite VS Code (na Windowsima i odjavite se/prijavite) |
| antivirus javlja upozorenje za `http/*.http` ili `wordlists/top-100.txt` | datoteke sadrže tipične napadne nizove i lozinke | to su nastavni materijali; po potrebi dodajte iznimku za mapu repozitorija |

Ako problem ostane, pokrenite `dotnet --info` i rezultat pošaljite predavaču.
