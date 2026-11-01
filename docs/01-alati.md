# 01 – Profesionalni alati za sigurnosno testiranje (Tjedan 1)

Program mikrokvalifikacije traži da ranjivost **pronađete alatom**, analizirate i ispravite, a zatim
**ponovnim skeniranjem ili testom** potvrdite da je otklonjena. Ova uputa pokazuje kako se alati iz
Tjedna 1 koriste nad aplikacijom VulnShop Akademija.

> Sve alate usmjeravajte **isključivo na vlastitu lokalnu instancu** (`http://localhost:5080`).
> Skeniranje tuđih sustava bez pisanog dopuštenja je kazneno djelo.

| Alat | Vrsta | Gdje se pokreće | Vježbe |
|---|---|---|---|
| OWASP ZAP | DAST (dinamička analiza), proxy, fuzzer | lokalno | Lab01–04, 07–09, 11 |
| Burp Suite Community | DAST, proxy, Repeater, Intruder | lokalno | Lab01–03, 07–12 |
| SonarQube for IDE | SAST u IDE-u | lokalno (VS, VS Code, Rider) | sve |
| Semgrep | SAST | lokalno | Lab07–09, 12, 13 |
| Roslyn analizatori (`AnalysisMode`) | SAST pri buildu | lokalno (i CI ako ga uključite) | Lab06, 07, 09, 13 |
| Security Code Scan | SAST (Roslyn) | lokalno | Lab03, 06–09, 13 |
| `dotnet list package --vulnerable`, NuGetAudit | SCA | lokalno + build | Lab05 |
| OSV-Scanner, Trivy, OWASP Dependency-Check | SCA | lokalno | Lab05 |
| CycloneDX | SBOM | lokalno | Lab05 |
| CyberChef, hashcat | analiza podataka, razbijanje hasheva | lokalno | Lab06, Lab12 |
| xUnit testovi | regresijski sigurnosni testovi | lokalno + **GitHub Actions (CI)** | sve |

U CI-ju (`.github/workflows/ci.yml`) pokreću se **samo build i testovi**. Svi ostali alati pokreću se
lokalno, na vašem računalu, nad pokrenutom aplikacijom ili izvornim kodom.

---

## 1. OWASP ZAP (Zed Attack Proxy)

Preuzimanje: <https://www.zaproxy.org/download/> (zahtijeva Javu – instalacijski paket je uključuje).

### 1.1 Automatsko skeniranje

1. Pokrenite aplikaciju: `dotnet run --project src/VulnShop.Api --launch-profile http`.
2. U ZAP-u: **Quick Start → Automated Scan** → *URL to attack*: `http://localhost:5080` → **Attack**.
3. Automatski *spider* ne zna za API endpointe (nema poveznica), pa je bolje ručno "nahraniti" ZAP:
   pošaljite zahtjeve iz `http/*.http` kroz ZAP kao proxy (vidi 1.2) ili ih otvorite u ZAP-ovu pregledniku.
4. Rezultati: kartica **Alerts** – očekujte npr. *SQL Injection* (Lab07), *Cross Site Scripting (Reflected)*
   (Lab08), *Remote OS Command Injection* (Lab09), *Missing Anti-clickjacking Header*,
   *X-Content-Type-Options Header Missing*, *CSP Header Not Set* (Lab04), *Application Error Disclosure* (Lab04).

### 1.2 Ručno istraživanje (Manual Explore) i ZAP kao proxy

1. **Quick Start → Manual Explore** → URL `http://localhost:5080/lab08/search?q=test` → **Launch Browser**.
   ZAP otvara preglednik koji sav promet šalje kroz ZAP.
2. Ili postavite ZAP kao proxy za curl: `curl -x http://127.0.0.1:8080 http://localhost:5080/api/lab07/products/search?q=Laptop`
   (ZAP po zadanome sluša na portu 8080).
3. Zahtjevi se pojavljuju u stablu **Sites** i kartici **History**. Desni klik na zahtjev →
   **Attack → Active Scan** pokreće ciljano skeniranje samo tog endpointa.

### 1.3 Fuzzer

1. U kartici **History** desni klik na zahtjev (npr. `GET /api/lab07/products/search?q=Laptop`) → **Attack → Fuzz…**
2. Označite vrijednost parametra (`Laptop`) → **Add… → Add… → Type: File Fuzzers** → npr.
   *jbrofuzz → Injection → SQL Injection* (ili **Type: File** i odaberite vlastitu datoteku).
3. **Start Fuzzer** i promatrajte stupce *Code* i *Size* – odstupanja otkrivaju ranjivost.
4. Lab11: zahtjev `POST /api/lab11/login`, označite vrijednost lozinke, *Type: File* →
   `wordlists/top-100.txt`. Pokušaj s drukčijim statusom (200) je pogođena lozinka.

### 1.4 Ponovno skeniranje nakon popravka

Nakon popravka ponovno pokrenite isti *Active Scan* / *Fuzz* nad istim endpointom i provjerite da je
alarm nestao (ZAP: **Report → Generate Report** prije i poslije, za usporedbu).

---

## 2. Burp Suite Community Edition

Preuzimanje: <https://portswigger.net/burp/communitydownload>.

1. **Proxy → Intercept → Open browser** – Burpov ugrađeni Chromium već koristi Burp kao proxy
   (`127.0.0.1:8080`; ako istodobno radi i ZAP, jednom od njih promijenite port).
2. U tom pregledniku otvorite `http://localhost:5080/lab08/search?q=test`. Zahtjev se vidi u
   **Proxy → HTTP history**. (Intercept isključite gumbom *Intercept is on/off* da promet teče.)
3. **Repeater** (Ctrl+R na zahtjevu): mijenjate zahtjev i šaljete ga ponovno – idealno za Lab01 (promjena
   ID-a narudžbe), Lab02 (dodavanje polja `role`), Lab03 (`url=`), Lab10 (negativna količina), Lab12 (krivotvoreni JWT).
4. **Intruder** (Ctrl+I): automatizirani napad.
   - Lab11 – brute force: zahtjev `POST /api/lab11/login` s tijelom `{"username":"ivana","password":"x"}`.
     U kartici **Positions** kliknite **Clear §**, označite `x` i **Add §**. Vrsta napada **Sniper**.
     U kartici **Payloads**: *Payload type: Simple list* → **Load…** → `wordlists/top-100.txt` → **Start attack**.
     Sortirajte rezultate po stupcu *Status* ili *Length* – pogođena lozinka vraća 200.
   - Lab11 – enumeracija: isti postupak, ali `§` oko korisničkog imena i lista imena (`ana`, `ivana`,
     `tomislav`, `petar` …) – razlika 404 / 401 otkriva postojeće korisnike.
   - Community Edition namjerno usporava Intruder; za 100 pokušaja to nije problem.
5. **Decoder**: Base64 / URL kodiranje (Lab06, Lab12).

---

## 3. SonarQube for IDE (ranije SonarLint)

- Visual Studio: **Extensions → Manage Extensions** → potražite *SonarQube for IDE* → instalirajte i ponovno pokrenite VS.
- VS Code: Extensions → *SonarQube for IDE* (SonarSource).
- Rider: **Settings → Plugins** → *SonarQube for IDE*.

Otvorite datoteke iz `src/VulnShop.Api/Labs/` – problemi se podcrtavaju izravno u editoru, a popis je u
prozoru *Error List* / *Problems*. Primjeri pravila: S2077 (SQL formatiran iz korisničkog unosa – Lab07),
S4790 (slab hash MD5 – Lab06), S5542 (ECB način – Lab06), S5144 (SSRF – Lab03),
S6418 (hardkodirana tajna – Lab12). Pojedina pravila za praćenje toka podataka (*taint analysis*)
dostupna su tek uz povezani SonarQube Server/Cloud (*Connected Mode*).

---

## 4. Semgrep

Instalacija: `pip install semgrep` (ili `brew install semgrep`; na Windowsima preko WSL-a ili Dockera:
`docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config p/owasp-top-ten /src`).

```bash
# u korijenu repozitorija
semgrep scan --config p/owasp-top-ten src/
semgrep scan --config p/csharp src/
semgrep scan --config p/secrets .
```

Očekivani nalazi: SQL upit spojen iz stringova (Lab07), `Process.Start` s korisničkim unosom (Lab09),
`TypeNameHandling.All` (Lab13), MD5 / ECB (Lab06), hardkodirane tajne (Lab06, Lab12).
Nakon popravka ponovite isti `semgrep scan` – nalaz za ispravljenu datoteku mora nestati.

---

## 5. .NET alati

### 5.1 Roslyn analizatori (SAST pri buildu)

Analizatori su ugrađeni u .NET SDK. Za stroži način dodajte u `src/VulnShop.Api/VulnShop.Api.csproj`
(unutar `<PropertyGroup>`):

```xml
<AnalysisMode>All</AnalysisMode>
<EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
```

i pokrenite `dotnet build`. Sigurnosna pravila (CA2100 – SQL iz korisničkog unosa, CA5350/CA5351 – slabi
kriptografski algoritmi, CA5358 – nesiguran način šifriranja (ECB), CA2326/CA2327 – `TypeNameHandling`
različit od `None`, CA3006 – command injection …) pojavit će se kao upozorenja. U repozitoriju ova
postavka namjerno nije uključena, kako upozorenja ne bi otkrila rješenja prije vježbe.

### 5.2 Ranjivi paketi: `dotnet list package` i NuGetAudit

```bash
dotnet list package --vulnerable --include-transitive
dotnet list package --outdated
```

Na grani `main` prvi upit ispisuje `Newtonsoft.Json 12.0.3` sa savjetom GHSA-5crp-9r3c-p9vr (High).
NuGet isto provjerava pri svakom *restoreu* (**NuGetAudit**) i javlja upozorenje **NU1903**
(NU1901 – low, NU1902 – moderate, NU1903 – high, NU1904 – critical). U projektima je postavljeno
`<WarningsNotAsErrors>NU1901;NU1902;NU1903;NU1904</WarningsNotAsErrors>` kako bi namjerno ranjiva verzija
ostala samo upozorenje. U stvarnim projektima preporučuje se suprotno: `<TreatWarningsAsErrors>` barem za NU1903/NU1904.

### 5.3 Security Code Scan

Security Code Scan (<https://security-code-scan.github.io/>) je Roslyn analizator usmjeren na sigurnost
(SQL injection, XSS, SSRF, slaba kriptografija). **Napomena o statusu:** projekt se već duže vrijeme ne
razvija aktivno (nova pravila i podrška za novije verzije C#-a ne stižu); i dalje radi kao NuGet paket ili
samostalni alat, ali za nove projekte radije koristite Roslyn analizatore (5.1), SonarQube for IDE i Semgrep. Pokretanje bez izmjene projekta:

```bash
dotnet tool install --global security-scan
security-scan SecureCodingAkademija.sln
```

---

## 6. Analiza ovisnosti (SCA) i SBOM

| Alat | Instalacija | Naredba nad repozitorijem |
|---|---|---|
| OSV-Scanner | <https://google.github.io/osv-scanner/> (`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, Homebrew, ili binarna datoteka s GitHuba) | `osv-scanner scan source -r .` |
| Trivy | <https://trivy.dev/> (`brew install trivy`, `choco install trivy`, Docker) | `trivy fs .` (za .NET čita `*.deps.json` / `packages.lock.json`; najprije `dotnet build`) |
| OWASP Dependency-Check | <https://owasp.org/www-project-dependency-check/> (CLI, Java) | `dependency-check --scan . --format HTML --out dc-report` (prvo preuzimanje NVD baze traje dugo; preporučuje se besplatan **NVD API ključ**: `--nvdApiKey <ključ>`) |
| CycloneDX (SBOM) | `dotnet tool install --global CycloneDX` | `dotnet-CycloneDX SecureCodingAkademija.sln -o sbom` (rezultat u mapi `sbom`; format i ostale opcije: `dotnet-CycloneDX --help`) |
| GitHub Dependabot | na GitHubu: **Settings → Code security → Dependabot alerts** | upozorenja i automatski PR-ovi za nadogradnju |

Dobra praksa za lanac opskrbe: zaključavanje verzija (`<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`
→ `packages.lock.json`, a u CI-ju `dotnet restore --locked-mode`), samo provjereni izvori paketa
(`nuget.config` s `<packageSourceMapping>`), provjera potpisa paketa i redovito ažuriranje.

---

## 7. Pomoćni alati: CyberChef i hashcat

- **CyberChef** (<https://gchq.github.io/CyberChef/>): Base64, heks, AES dešifriranje (Lab06 dio B),
  *JWT Decode* / *JWT Sign* (Lab12). Može se preuzeti i koristiti lokalno (offline).
- **hashcat** (<https://hashcat.net/hashcat/>): razbijanje hasheva rječnikom.
  - Lab06 (MD5): `hashcat -m 0 -a 0 hashes.txt wordlists/top-100.txt`
  - Lab12 (JWT HS256): `hashcat -m 16500 -a 0 token.txt wordlists/top-100.txt`
  - Prikaz razbijenih: dodajte `--show`.
  - Online alternativa za nesoljene hasheve: <https://crackstation.net/> (samo za hasheve iz ove vježbe!).

---

## 8. Ponovna provjera testovima (regresija)

Svaki popravak dokazuje se testom:

```bash
dotnet test --filter "Category=Security&Lab=Lab07"   # sigurnosni testovi vježbe – nakon popravka zeleni
dotnet test --filter "Category=Functional"           # funkcionalnost nije narušena
```

Isti testovi se pokreću u GitHub Actionsu na svakom pushu; sažetak po vježbi vidljiv je u kartici
**Actions** → odabrani *run* → **Summary** (anotacija *Lab sažetak*).
