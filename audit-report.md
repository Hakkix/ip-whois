# Auditointiraportti: hakkix/ip-whois

| Kenttä | Arvo |
|---|---|
| Repo | https://github.com/hakkix/ip-whois |
| Commit | `3996156165bff3196002b331dd51f31a6bbeb5e4` |
| Päivämäärä | 2026-05-29 |
| Havaitut kielet | JavaScript (app.js 64 riviä), HTML (index.html), CSS (base.css + style.css), JSON (vercel.json) |
| Koko | 7 tiedostoa, ~33 KB |
| Stack | Vanilla frontend, ei rakennusaskelta, deploy Verceliin |

---

## Scorecard

| Alue | Pisteet | Arvosana |
|---|---|---|
| Tietoturva (35 %) | 50 | D |
| Koodin laatu (30 %) | 55 | D |
| Riippuvuudet & lisenssit (20 %) | 82 | B |
| Dokumentaatio (15 %) | 50 | D |
| **Painotettu kokonaispiste** | **58** | **D** |

---

## Yhteenveto

IP WHOIS on tiivis, selainpohjainen hakutyökalu IPv4- ja IPv6-osoitteille. Se ei käytä npm-riippuvuuksia, mikä eliminoi koko toimitusketjun haavoittuvuusriskin — tämä on projektin selkein vahvuus. Vakavimpana ongelmana on **XSS-haavoittuvuus**: ulkoisten API-rajapintojen (RDAP, ipinfo.io, ipwho.is, ipapi.co) palauttamia merkkijonoja syötetään suoraan `innerHTML`-kutsuihin ilman sanitointia, jolloin mikä tahansa kompromissoitu tai haitallinen API-vastaus voi suorittaa JavaScript-koodia käyttäjän selaimessa. Lisäksi **Content-Security-Policy**-otsake puuttuu kokonaan, mikä maksimoi XSS:n vaikutuksen. Toiminnallisena bugina `copyToClipboard`-funktio kutsutaan kahdesti per klikki. Testit ja CI-putki puuttuvat täysin.

---

## A. Koodin laatu

### [HIGH] Toiminnallinen bugi: copyToClipboard kutsutaan kahdesti

**Tiedosto:** `app.js:61`

```js
// Nykyinen (virheellinen):
flashButton(ex, (await copyToClipboard(t))?'copied':'failed', !(await copyToClipboard(t)));

// Ongelma: copyToClipboard(t) suoritetaan kaksi kertaa.
// Jos ensimmäinen onnistuu ja toinen epäonnistuu → teksti näyttää "copied" mutta
// error-tyyli päälle, tai päinvastoin. Lisäksi leikepöytäkirjoitus tehdään turhaan kahdesti.
```

**Korjaus:**
```js
const ok = await copyToClipboard(t);
flashButton(ex, ok ? 'copied' : 'failed', !ok);
```

### [MEDIUM] Kuollut koodi: tyhjä if-lohko

**Tiedosto:** `app.js:17`

```js
if(s.includes(':') && /^\[?[0-9a-fA-F:.]+\]?::?[0-9a-fA-F:.]*:\d+$/.test(s)
   && s.split(':').length<8 && !s.includes('::ffff')) { }
// Lohkossa ei ole mitään. Ehto evaluoidaan turhaan.
```

### [MEDIUM] Erittäin tiivis koodirakenne — ylläpidettävyys heikko

Koko `app.js` (64 riviä) on kirjoitettu yksirivisiksi lohkoiksi, joissa loogisesti erilliset funktiot (`buildReport`, `renderResult`) ovat satojen merkkien levyisiä rivejä. Yksikään rivi ei ole kommentoitu. Tämä tekee bugietsinnästä ja refaktoroinnista erittäin hidasta.

### [LOW] Käyttämätön parametri sisemmässä funktiossa

**Tiedosto:** `app.js:25`

```js
const inC=(b,m)=> (x & m[1])===m[0];
// Parametri b (johon siirretään ip-merkkijono) ei koskaan käytetä.
// Funktio käyttää sulkeuman x:ää, mikä toimii, mutta johtaa harhaan.
```

### [LOW] Ei testejä

Ei yhtään testitiedostoa. IPv4/IPv6-validointilogiikka ja `isReserved`-funktio sisältävät useita raja-tapauksia, jotka hyötyisivät yksikkötesteistä.

### [LOW] Ei CI/CD-putkea

`.github/workflows/`-hakemistoa ei ole. Automaattinen laaduntarkistus puuttuu.

---

## B. Tietoturva

### [HIGH] XSS ulkoisten API-vastausten kautta

**Tiedosto:** `app.js:51–55`

Useat `innerHTML`-sijoitukset käyttävät suoraan ulkoisten rajapintojen palauttamia kenttiä:

| Sijoituspaikka | Lähde |
|---|---|
| `${r.summary.registrant}` | RDAP `name`-kenttä |
| `${r.network.name}` | RDAP `name` |
| `${r.network.handle}` | RDAP `handle` |
| `${r.network.type}` | RDAP `type` |
| `${r.location.city}` | ipinfo.io / ipwho.is / ipapi.co |
| `${r.location.region}` | sama |
| `${r.location.country}` | sama |

Jos mikä tahansa näistä API:sta palauttaa haitallista HTML:ää kentissään (esim. RDAP `name: "<img src=x onerror=alert(document.cookie)>"`), koodi suorittuu käyttäjän selaimessa. Hyökkäys vaatii API-kompromissin tai MitM-tilanteen, mutta kohdistuu kaikkiin saman IP:n hakeneisiin käyttäjiin.

**Korjaus:** sanitoi kaikki API-data ennen `innerHTML`-sijoitusta:
```js
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```
Tai vaihda `innerHTML`-rakentaminen `document.createElement`/`textContent`-pohjaiseksi DOM-rakentamiseksi.

### [HIGH] Content-Security-Policy puuttuu

**Tiedosto:** `vercel.json`

`vercel.json` asettaa `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` ja `Referrer-Policy` — nämä ovat hyviä — mutta `Content-Security-Policy`-otsake puuttuu kokonaan. Ilman CSP:tä XSS-haavoittuvuuden vaikutus on maksimaalinen.

**Esimerkki CSP:stä** (tiukka mutta yhteensopiva tämän sovelluksen kanssa):
```json
{
  "key": "Content-Security-Policy",
  "value": "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src https://rdap-bootstrap.arin.net https://*.arin.net https://*.ripe.net https://*.apnic.net https://*.lacnic.net https://afrinic.net https://ipinfo.io https://ipwho.is https://ipapi.co; img-src 'none'; frame-ancestors 'none'"
}
```

### [LOW] Deprecated `document.execCommand('copy')`

**Tiedosto:** `app.js:47`

`document.execCommand('copy')` on poistettu käytöstä kaikissa moderneissa selaimissa. Se toimii vielä joissain ympäristöissä, mutta voidaan poistaa tai se voidaan korvata luotettavammalla fallback-mekanismilla.

### [INFO] Google Fonts ladataan CDN:ltä — GDPR-huomio

`index.html:7-9` lataa fontit suoraan `fonts.googleapis.com`-palvelimelta, jolloin Google saa käyttäjän IP-osoitteen. EU-käyttäjille tämä voi vaatia GDPR-huomion (tietosuojaseloste / self-hosting).

---

## C. Dokumentaatio

### [MEDIUM] README on suppea mutta toimiva

`README.md` (27 riviä) kattaa: sovelluksen kuvauksen, käyttöohjeen, esimerkit, tietolähteet ja yhden teknisen huomion (IPv6 + ipapi.co). **Puuttuu:** kehittäjäohje (miten ajaa lokaalisti), arkkitehtuurikuvaus, kontribuointiohjeet.

### [LOW] Puuttuvat vakiotiedostot

| Tiedosto | Tila |
|---|---|
| `LICENSE` | ✅ Apache 2.0 |
| `README.md` | ✅ (suppea) |
| `CONTRIBUTING.md` | ❌ Puuttuu |
| `CHANGELOG.md` | ❌ Puuttuu |
| `SECURITY.md` | ❌ Puuttuu (erityisen tärkeä, koska työkalu käsittelee verkkoanalytiikkatietoja) |

### [LOW] Ei koodidokumentaatiota

`app.js`:ssä ei ole yhtään JSDoc-kommenttia tai funktioselitettä. Funktioiden tarkoitus selviää nimistä, mutta monimutkaisemmat algoritmit (`validIPv6`, `isReserved`, `buildReport`) hyötyisivät lyhyistä selityksistä.

---

## D. Riippuvuudet & lisenssit

### [INFO] Ei npm-riippuvuuksia — hyvä

Projektissa ei ole `package.json`-tiedostoa eikä `node_modules`-kansiota. Kaikki toiminnallisuus on vanilla JS:ää. Tämä eliminoi npm-toimitusketjuriskit kokonaan.

### [INFO] Ajonaikaiset API-riippuvuudet (ei versiohallintaa)

| Palvelu | Rooli | Fallback |
|---|---|---|
| `rdap-bootstrap.arin.net` | RDAP-haku (pakollinen) | Ei |
| `ipinfo.io` | Geolokatio (1.) | Kyllä (cascade) |
| `ipwho.is` | Geolokatio (2.) | Kyllä |
| `ipapi.co` | Geolokatio (3.) | Kyllä |
| `fonts.googleapis.com` | Fontit | Ei (system-ui fallback CSS:ssä) |

RDAP-bootstrap-palvelun kaatuminen tai vastauksen muuttuminen rikkoo sovelluksen täysin.

### [INFO] Lisenssi: Apache 2.0

Apache 2.0 on permissiivinen lisenssi. Ei yhteensopivuusongelmia. Sovelluksessa ei käytetä GPL-lisensoitua koodia.

---

## Suositukset (priorisoitu)

1. **[HIGH] Sanitoi kaikki API-data ennen innerHTML-syöttöä.** Luo `escHtml()`-apufunktio tai refaktoroi DOM-rakentaminen `textContent`-pohjaiseksi. Koskee rivejä 51–57.

2. **[HIGH] Lisää Content-Security-Policy `vercel.json`-tiedostoon.** Tämä rajoittaa XSS:n vaikutusta dramaattisesti vaikka yllä oleva korjaus viivästyisi.

3. **[MEDIUM] Korjaa `copyToClipboard`-kaksoiskulkubugi** rivillä 61 tallentamalla tulos muuttujaan.

4. **[MEDIUM] Poista tyhjä if-lohko** riviltä 17 (`detectIPVersion`).

5. **[LOW] Lisää `SECURITY.md`**, jossa kerrotaan miten tietoturvaongelmista raportoidaan.

6. **[LOW] Lisää yksikkötestit** IP-validointilogiikalle (esim. Vitest tai Jest ilman bundleria).

7. **[LOW] Lisää GitHub Actions -workflow** joka ajaa ESLint-tarkistuksen PR:lle.

---

## Liite: ajetut työkalut ja tulosteet

| Työkalu | Tulos |
|---|---|
| `git clone --depth 1` | OK |
| `grep -rn "innerHTML"` | 3 osumaa (rivit 51, 57, 58) |
| `grep -rniE "(api[_-]?key\|secret\|password\|token)"` | 0 osumaa — ei kovakoodattuja salaisuuksia |
| `grep -rn "TODO\|FIXME\|XXX"` | 0 osumaa |
| `grep -n "eval\|document\.write"` | 0 osumaa |
| `grep -n "execCommand"` | 1 osuma (rivi 47, deprecated fallback) |
| `grep -n "fetch("` | 2 osumaa (rivit 28, 32) |
| `semgrep` | Ei asennettu ympäristössä |
| `gitleaks` | Ei asennettu ympäristössä |
| `npm audit` | N/A — ei package.json |
| `bandit` | N/A — ei Python-koodia |
| `eslint` | Ei konfiguraatiota repossa, ei ajettu |

Puuttuvat työkalut (semgrep, gitleaks) olisivat voineet tunnistaa lisää tietoturvahaasteita. Raportin löydökset perustuvat manuaaliseen koodianalyysin, grep-hakuihin ja staattisin tarkistuksiin.
