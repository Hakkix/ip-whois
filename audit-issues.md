# Audit-löydökset GitHub-issuina: hakkix/ip-whois

Järjestetty vakavuuden mukaan (vakavimmat ensin).

---

### [HIGH] XSS-haavoittuvuus: API-vastausten data syötetään suoraan innerHTML:ään

**Tiedosto:** `app.js:51–55`

**Kuvaus:**
`renderResult()`-funktio rakentaa DOM:n template-literaaleilla ja sijoittaa tuloksen `innerHTML`:ään. Useat kentät tulevat suoraan ulkoisten RDAP- ja geolokatio-API:en vastauksista ilman sanitointia:

- `r.summary.registrant` ← RDAP `name`
- `r.network.name`, `r.network.handle`, `r.network.type` ← RDAP-kentät
- `r.location.city`, `r.location.region`, `r.location.country` ← ipinfo.io / ipwho.is / ipapi.co

Jos mikä tahansa näistä API:sta palauttaa HTML-sisältöä (esim. `"name": "<img src=x onerror=alert(1)>"`) — esimerkiksi hyökkäyksen, kompromissin tai välimieshyökkäyksen (MitM, HTTP-yhteys ilman HTTPS:ää) seurauksena — koodi suoritetaan käyttäjän selaimessa.

**Suositus:**
1. Luo sanitointifunktio:
   ```js
   function esc(s) {
     return String(s ?? '')
       .replace(/&/g,'&amp;').replace(/</g,'&lt;')
       .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
   }
   ```
2. Käytä `esc()` kaikkiin API-dataa sisältäviin template-literaalin interpolointeihin.
3. Pitkällä tähtäimellä: vaihda `innerHTML`-rakentaminen `document.createElement`/`textContent`-pohjaksi.

**Labels:** `security`, `bug`, `high-priority`

---

### [HIGH] Content-Security-Policy puuttuu HTTP-otsakkeista

**Tiedosto:** `vercel.json`

**Kuvaus:**
`vercel.json` asettaa kolme hyödyllistä turvaotsakkeet (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`), mutta `Content-Security-Policy` puuttuu kokonaan. Ilman CSP:tä XSS-haavoittuvuudet (ks. edellinen issue) antavat hyökkääjälle täyden pääsyn sivun kontekstiin: evästeet, localStorage, API-pyynnöt.

**Suositus:**
Lisää `vercel.json`-tiedostoon:
```json
{
  "key": "Content-Security-Policy",
  "value": "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src https://rdap-bootstrap.arin.net https://*.arin.net https://*.ripe.net https://*.apnic.net https://*.lacnic.net https://afrinic.net https://ipinfo.io https://ipwho.is https://ipapi.co; img-src 'none'; frame-ancestors 'none'"
}
```

**Labels:** `security`, `enhancement`, `high-priority`

---

### [MEDIUM] Toiminnallinen bugi: copyToClipboard kutsutaan kahdesti per klikki

**Tiedosto:** `app.js:61`

**Kuvaus:**
`flashButton`-kutsussa `copyToClipboard(t)` evaluoidaan kahdesti:

```js
// Nykyinen (virheellinen):
flashButton(ex, (await copyToClipboard(t))?'copied':'failed', !(await copyToClipboard(t)));
```

Tämä aiheuttaa:
1. Kaksi leikepöytäkirjoitusta per klikki.
2. Jos ensimmäinen kirjoitus onnistuu ja toinen epäonnistuu (esim. kilpailutilanteessa), `flashButton` saa ristiriitaiset argumentit: teksti `'copied'` mutta `err=true` → virheellinen visualinen tila.

**Suositus:**
```js
const ok = await copyToClipboard(t);
flashButton(ex, ok ? 'copied' : 'failed', !ok);
```

**Labels:** `bug`, `medium-priority`

---

### [MEDIUM] Kuollut koodi: tyhjä if-lohko detectIPVersion-funktiossa

**Tiedosto:** `app.js:17`

**Kuvaus:**
Seuraava if-lohko evaluoi monimutkaiseen regexiin perustuvan ehdon mutta ei tee mitään sen perusteella:

```js
if(s.includes(':') && /^\[?[0-9a-fA-F:.]+\]?::?[0-9a-fA-F:.]*:\d+$/.test(s)
   && s.split(':').length<8 && !s.includes('::ffff')) { }
```

Lohkossa ei ole koodia. Ehdon tarkoitus on epäselvä: pitäisikö se hylätä syöte, muokata sitä, vai onko logiikka jäänyt kesken? Kuollut koodi harhaanjohtaa ylläpitäjää.

**Suositus:** Poista tyhjä lohko tai lisää siihen tarkoituksenmukainen logiikka kommentteineen.

**Labels:** `bug`, `code-quality`

---

### [LOW] SECURITY.md puuttuu

**Tiedosto:** (repositorion juuressa)

**Kuvaus:**
Projektilta puuttuu `SECURITY.md`-tiedosto, joka kertoisi miten tietoturvaongelmista raportoidaan vastuullisesti. Tämä on erityisen tärkeää sovellukselle, joka tekee pyyntöjä ulkoisiin API-palveluihin käyttäjän syöttämän datan perusteella.

**Suositus:**
Luo `SECURITY.md`, jossa mainitaan:
- Yhteystieto/sähköposti haavoittuvuuksien raportointiin
- Odotettu vasteaika
- Onko bug bounty -ohjelma olemassa

**Labels:** `documentation`, `security`

---

### [LOW] Deprecated `document.execCommand('copy')` leikepöytäfallback

**Tiedosto:** `app.js:47`

**Kuvaus:**
`copyToClipboard`-funktion fallback-polku käyttää `document.execCommand('copy')`:a, joka on merkitty poistetuksi kaikissa moderneissa selaimissa (poistettu Chromesta, poistuu muistakin). Tällä hetkellä `navigator.clipboard.writeText` on laajasti tuettu (kaikki modernit selaimet), joten fallbackia ei käytännössä enää tarvita.

**Suositus:**
Poista `execCommand`-fallback tai korvaa se `prompt()`-pohjaisella varakopiointiohjeella jos halutaan tukea vanhempia selaimia.

**Labels:** `enhancement`, `low-priority`

---

### [LOW] Ei yksikkötestejä — erityisesti IP-validointilogiikalle

**Tiedosto:** `app.js` (`validIPv4`, `validIPv6`, `isReserved`, `detectIPVersion`)

**Kuvaus:**
Projektissa ei ole yhtään testitiedostoa. IP-validointilogiikka käsittelee useita haastavia raja-tapauksia (IPv4-mapped IPv6, zone-identifierit, suluissa olevat IPv6-osoitteet, portin erottaminen), joissa regressiobugi olisi helppo tehdä.

**Suositus:**
Lisää testitiedosto esim. `app.test.js` Vitest- tai Jest-kirjastolla (molemmat toimivat ilman bundleria). Testaa ainakin:
- Kelvolliset IPv4 ja IPv6
- Epäkelvolliset syötteet (tekstiä, tyhjä, pelkkä portti)
- IPv4-mapped IPv6 (`::ffff:8.8.8.8`)
- Varatut osoitteet (`192.168.1.1`, `::1`, `fc00::1`)

**Labels:** `testing`, `code-quality`

---

### [INFO] Google Fonts CDN — GDPR-huomio

**Tiedosto:** `index.html:7-9`

**Kuvaus:**
Fontit ladataan suoraan `fonts.googleapis.com`-palvelimelta, jolloin Google saa käyttäjän IP-osoitteen jokaisen sivulatauksen yhteydessä. EU-alueella tämä voi vaatia huomion tietosuojaselosteessa tai siirtymistä self-hosting-ratkaisuun.

**Suositus:**
Harkitse fonttien self-hostingia `@font-face`-säännöillä tai hyväksy nykyinen käytäntö ja mainitse se tietosuojaselosteessa.

**Labels:** `privacy`, `enhancement`, `info`

---

### [INFO] CONTRIBUTING.md ja CHANGELOG.md puuttuvat

**Tiedosto:** (repositorion juuressa)

**Kuvaus:**
Projektissa ei ole `CONTRIBUTING.md`- eikä `CHANGELOG.md`-tiedostoa. Nämä helpottavat ulkopuolisten kontribuoijien onboarding-prosessia ja tekevät julkaisuhistoriasta läpinäkyvämmän.

**Labels:** `documentation`
