# Cookie Defense

Chrome-laajennus (Manifest V3), joka

1. **analysoi** avoinna olevan sivuston (tai koko selaimen) evästeet: luokittelee ne, purkaa evästeen arvon rakenteen (JWT/base64/hex/JSON/UUID/GA-tunniste) ja pisteyttää attack-surface-riskin per eväste,
2. **raportoi** löydökset ihmisluettavana Markdown-tiedostona, ja
3. **peittää** ei-toiminnallisten evästeiden arvot muoto-validilla valedatalla — todellisen seurantatunnisteen sijaan sivusto/kolmas osapuoli saa syntaktisesti uskottavan mutta merkityksettömän arvon.

Kirjautumis-, istunto- ja muut toiminnalliset evästeet **jätetään aina koskematta**. Politiikka evästeille joita luokittelutietokanta ei tunnista: **"jos ei ole whitelistattu, on mustalistattu"**, säädettävissä viisiportaisella aggressiivisuustasolla — ks. [Luokittelupolitiikka](#luokittelupolitiikka-whitelist--blacklist) alla. Tämä on tietoinen valinta oletetun fail-safe-käytöksen sijaan; se kasvattaa peittokattavuutta merkittävästi mutta ei ole riskitön — siksi jokainen peitetty arvo myös varmuuskopioidaan (ks. [Varmuuskopiointi ja palautus](#varmuuskopiointi-ja-palautus)).

## Miksi

Useimmat avoimen lähdekoodin työkalut (Cookie AutoDelete, Privacy Badger, Consent-O-Matic…) joko **poistavat** evästeet tai estävät niiden asettamisen kokonaan. Se rikkoo usein sivuston toiminnan. Tämä työkalu jättää evästeen olemassa olevaksi (sivusto toimii), mutta arvo on hyödytöntä valedataa — seurantaprofiili turmeltuu ilman että käyttäjän kokemus muuttuu.

Vastaavaa valmista avoimen lähdekoodin ratkaisua ei löytynyt GitHub-haulla (heinäkuu 2026). Lähin konseptillinen esikuva on [TrackMeNot](https://github.com/vtoubiana/TrackMeNot) (peittää hakukyselyt kohinalla, ei evästeitä).

## Arkkitehtuuri

```
extension/
  manifest.json         MV3-manifesti (cookies + storage + tabs -oikeudet)
  background.js         Service worker: analyze/obfuscate-logiikka, chrome.cookies.onChanged-kuuntelu
  popup.html/js/css     Popup-käyttöliittymä (per-tabi analyysi ja ohjaus)
  lib/classify.js       Luokittelu bundlatun tietokannan perusteella
  lib/reverse.js        Evästeen arvon rakenteen purku (JWT/base64/hex/JSON/UUID/GA-tunniste)
  lib/risk.js           Attack-surface-riskipisteytys per eväste (heuristinen)
  lib/report.js         Markdown-raporttien muotoilu
  lib/lorem.js          Muoto-validi valedatageneraattori (ks. alla)
  lib/heuristic.js      Toissijainen luokitin tietokannan tunnistamattomille evästeille (5 tasoa)
  lib/settings.js       Aggressiivisuustason, whitelistin ja globaalin auto-suojan tallennus (chrome.storage.local)
  lib/backup.js         Peitettyjen arvojen varmuuskopiolistan hallinta (puhdas logiikka)
  lib/i18n.js           chrome.i18n-kääre + kategoria-/riskitason näyttönimet
  _locales/fi, _locales/en   Käyttöliittymä- ja raporttitekstit (ks. Kielituki)
  data/cookie-database.json   Generoitu tiedosto (ks. alla), ei muokata käsin
third_party/
  open-cookie-database.csv        Upstream-lähdedata (Apache-2.0)
  local-overrides.csv             Omat OSINT-löydetyt lisäykset, sama skeema — ks. alla
  LICENSE-open-cookie-database    Alkuperäinen lisenssi
scripts/
  build_cookie_db.py    CSV(t) → JSON-konversio
  generate_icons.py     Työkalupalkin ikonit (puhdas Python, ei riippuvuuksia)
```

Luokittelu perustuu [Open Cookie Databaseen](https://github.com/jkwakman/Open-Cookie-Database) (Apache-2.0, ~2000 tunnettua evästeimeä + ~260 etuliitesääntöä) täydennettynä `third_party/local-overrides.csv`:llä (sama CSV-skeema, ei katoa upstream-päivityksissä). Kategoriat `Analytics`, `Marketing` ja `Personalization` merkitään peitettäviksi; `Functional`, `Necessary` ja `Security` eivät. Evästeet joita kumpikaan tietokanta ei tunnista menevät `lib/heuristic.js`:n läpi — ks. seuraava osio.

## Luokittelupolitiikka: whitelist / blacklist

Evästeet joita tietokanta (upstream + local-overrides) ei tunnista **peitetään oletuksena**, ellei jokin suojaussignaali suojaa niitä (`lib/heuristic.js`). Suojaussignaaleja on kolme, järjestetty heikoimmasta vahvimpaan näytöksi:

1. **Nimi/lippu-yhdistelmä (heikoin):** eväste on **sekä** `HttpOnly` **että** sessio-eväste (ei pysyvä).
2. **Nimikuvio:** evästeen nimi täsmää kuvioon joka viittaa sessioon/kirjautumiseen (`session`, `auth`, `token`, `login`, `jwt`, `csrf`/`xsrf`, `refresh`/`access`/`id`-token, `sid`).
3. **Sisältö (vahvin):** eväste dekoodautuu JWT:ksi jonka payloadissa on sessio-/autentikointityyppinen kenttä (`sub`, `exp`, `iat`, `aud`, `iss`, `jti`, `nbf`, `scope`, `token_type`).

### Aggressiivisuustaso (1–5, popupin Asetukset-valikosta)

Jokainen taso poistaa käytöstä yhden signaalin lisää, heikoimmasta alkaen. Tason 5 valinta vaatii eksplisiittisen vahvistuksen popupissa.

| Taso | Käytössä olevat suojaussignaalit | Vaikutus |
|---|---|---|
| 1 — Minimaalinen | Heuristiikka pois kokonaan | Vain tietokannan nimeltä tunnistamat evästeet peitetään. Tuntematon ei koskaan kosketa. |
| 2 — Tasapainoinen *(oletus)* | Kaikki 3 | Matalin väärien positiivisten riski deny-by-default-politiikassa. |
| 3 — Laaja | Nimikuvio + sisältö | HttpOnly+sessio-yhdistelmä ei enää yksin suojaa. |
| 4 — Aggressiivinen | Vain sisältö (JWT) | Nimikuvio ei enää suojaa — vain evästeen arvosta luettu sessiotieto suojaa. |
| 5 — Scorched earth | Ei mitään | Vain käyttäjän oma eksplisiittinen whitelist (ks. alla) suojaa. Rikkoo todennäköisesti kirjautumisia. |

Käyttäjän oma whitelist (`lib/settings.js`, tallennettu `chrome.storage.local`:iin) ohittaa **kaikki** tasot — kertaalleen "Merkitse turvalliseksi" -painikkeella vahvistettu eväste ei enää koskaan mene tason kautta.

**Tärkeä empiirinen huomio, joka muokkasi näitä sääntöjä:** pelkkä `HttpOnly`-lippu EI riitä erottelemaan mainosseurantaa autentikoinnista. Laajan, oikeasta selaimesta kerätyn evästejoukon läpikäynti osoitti, että "ei HttpOnly" esiintyy sekä valtaosassa vahvistetuista mainostrackereista **että** huomattavassa osassa vahvistetuista kirjautumis-/refresh-token-evästeistä (esim. token-uusinta vaatii usein JS-luettavuutta). Siksi `HttpOnly` on käytössä vain yhdistettynä `session`-lippuun, ei yksinään, ja vain tasoilla 1–2.

Tämä käännetty fail-safe→fail-deny-oletus **kasvattaa väärien positiivisten riskiä** korkeammilla tasoilla: jokin todellinen toiminnallinen eväste, jota tietokanta ei tunnista eikä heuristiikka tunnista suojattavaksi, voidaan peittää ja rikkoa jokin sivuston toiminto (esim. kirjautuminen, ostoskori). Tähän on varmuuskopiointi ja palautus (seuraava osio) — testaa silti huolella erityisesti tileillä joiden toimivuus on tärkeää ennen kuin nostat tasoa tai luotat automaattiseen jatkuvaan suojaan arkaluontoisilla sivustoilla.

## Varmuuskopiointi ja palautus

Joka kerta kun laajennos peittää evästeen arvon, alkuperäinen (todellinen) arvo tallennetaan ensin `chrome.storage.local`:iin (`lib/backup.js`) — ei koskaan lähetetä minnekään, ei synkronoidu Chrome-tilin kautta. Tämä on suunniteltu erityisesti korkeampien aggressiivisuustasojen turvaverkoksi.

- **Palauta** (popupin "Tämä sivu" -näkymässä, "Viimeksi peitetyt tällä sivustolla" -osio): kirjoittaa alkuperäisen arvon takaisin kertaluontoisesti — käytä jos jokin sivu meni rikki peiton takia.
- **Merkitse turvalliseksi**: sama kuin Palauta, mutta lisää evästeen nimen pysyvään käyttäjä-whitelistiin — sitä ei enää koskaan peitetä, millään tasolla.
- **Vanheneminen:** varmuuskopiot poistetaan automaattisesti 14 vuorokauden jälkeen, ja niitä säilytetään korkeintaan 500 kappaletta (vanhimmat pudotetaan ensin) — koska varmuuskopio on kopio oikeasta evästearvosta (mahdollisesti sessio-/tunnistetietoa), sitä ei säilytetä loputtomiin.
- Uudelleen peittäminen samalle (domain, nimi, path) -yhdistelmälle korvaa vanhan varmuuskopion, jos peitetty arvo ei ole laajennoksen oma edellinen valedata (ts. sivuston asettama aidosti uusi arvo varmuuskopioidaan, laajennoksen oman valedatan "kaiku" ei).

## Asennus Macille (kehitystila)

1. Avaa Chrome → `chrome://extensions`
2. Kytke "Developer mode" päälle (oikea yläkulma)
3. "Load unpacked" → valitse `cookie-defense/extension`-kansio
4. Laajennoksen kuvake ilmestyy työkalupalkkiin

Ei vaadi Chrome Web Storea eikä koodin allekirjoitusta — pelkkä paikallinen asennus riittää.

## Kielituki (i18n)

Käyttöliittymä ja ladattavat raportit ovat suomeksi ja englanniksi (`extension/_locales/fi`, `extension/_locales/en`). Chrome valitsee kielen automaattisesti selaimen käyttöliittymäkielen perusteella (`chrome.i18n`); jos selain on jollain muulla kielellä, käytetään `manifest.json`:n `default_locale`-arvoa (`en`).

Sisäiset tunnisteet (evästekategoriat, riskitasot) ovat aina vakaita englanninkielisiä avaimia (esim. `"high"`, `"Analytics"`) riippumatta näyttökielestä — niitä käytetään mm. CSS-luokkina ja vertailuissa koodissa, ja `lib/i18n.js` kääntää ne näyttötekstiksi vasta käyttöliittymässä/raportissa. Uuden kielen lisääminen: kopioi `extension/_locales/en/messages.json` uudeksi lokaaliksi ja käännä `message`-kentät; avainjoukon on pysyttävä samana (`tests/smoke.test.mjs` tarkistaa tämän automaattisesti).

## Käyttö

### Tämä sivu -välilehti

- **Asetukset** (popupin yläreunan avautuva paneeli): aggressiivisuustaso 1–5 (ks. [Luokittelupolitiikka](#luokittelupolitiikka-whitelist--blacklist)) ja **"Peitä automaattisesti kaikilla sivustoilla"** -kytkin — kun päällä, jatkuva suoja (ks. alla) kattaa kaikki sivustot ilman että per-sivusto-kytkintä tarvitsee erikseen käydä päällä jokaisella sivulla. Ei retroaktiivinen: koskee vain jatkossa (uudelleen)asetettavia evästeitä, ei jo olemassa olevia (käytä "Peitä kaikki tunnistetut seurantaevästeet" niihin).
- **Analysoi tämä sivu** listaa nykyisen välilehden evästeet: luokka, riskitaso (Matala/Keskitaso/Korkea, tai Low/Medium/High englanniksi) ja rakenneanalyysin yhteenveto (esim. "JWT — kentät: sub, email, iat").
- **Näytä dekoodatut arvot** -kytkin: oletuksena dekoodatut kentät (esim. JWT-payloadin arvot) näytetään redaktoituina (`abc…(42 merkkiä)`) tietovuodon välttämiseksi raportissa. Kytkimellä näet oikeat arvot popupissa.
- **Peitä nyt** korvaa kertaluontoisesti kaikki peitettävissä-luokan evästeiden arvot.
- **Peitä automaattisesti tällä sivustolla** ottaa käyttöön jatkuvan suojan yhdelle sivustolle kerrallaan: kun sivusto (uudelleen)asettaa jonkin peitettävän evästeen, laajennos ylikirjoittaa sen välittömästi `chrome.cookies.onChanged`-tapahtuman kautta. (Asetuksista löytyvä globaali kytkin tekee saman kaikille sivustoille kerralla, ks. yllä.)
- **Lataa raportti (.md)** tallentaa attack-surface-raportin nykyisestä sivusta.
- **Viimeksi peitetyt tällä sivustolla** -osio (näkyy vain jos jotain on peitetty): Palauta/Merkitse turvalliseksi -napit, ks. [Varmuuskopiointi ja palautus](#varmuuskopiointi-ja-palautus).

### Koko selain -välilehti

- **Skannaa koko selain** hakee `chrome.cookies.getAll({})`-kutsulla jokaisen selaimeen tallennetun evästeen kaikista domaineista — ei vain auki olevan välilehden — ja näyttää koosteen: eväste-/domainmäärät, riskijakauma, kuinka moni ei ole HttpOnly/Secure, JWT-määrä, kategoriajakauma.
- **Peitä kaikki tunnistetut seurantaevästeet (koko selain)** on erillinen, varmistusdialogilla suojattu toiminto — se muuttaa evästeitä *kaikilla* domaineilla, ei vain nykyisellä sivulla. Käytä harkiten.
- **Lataa raportti (.md)** tallentaa koko selaimen tilannekuvan, korkeimman riskin evästeet ensin.

## Attack-surface-riskipisteytys (heuristinen, ei sertifioitu)

`lib/risk.js` pisteyttää jokaisen evästeen näiden tekijöiden perusteella (painot ovat karkeita nyrkkisääntöjä, ei tieteellisesti kalibroituja):

| Tekijä | Miksi se on riski |
|---|---|
| Luokka Analytics/Marketing/Personalization | Eväste on suunniteltu käyttäjän seurantaan |
| Ei `HttpOnly` | Sivun oma JS (ja siten XSS) pääsee lukemaan arvon |
| Ei `Secure` | Voi kulkea salaamattoman HTTP:n yli |
| `SameSite=None` | Lähtee myös sivustojenvälisissä pyynnöissä |
| Domain-jaettu (ei host-only) | Näkyy koko alidomeeniperheelle |
| Pitkä voimassaolo (>180 vrk) | Mahdollistaa pitkäkestoisen profiloinnin |
| JWT sisältää PII-tyyppisiä kenttiä (email, sub, user_id…) | Suora henkilötietoviite evästeen sisällä |

Rakenneanalyysi (`lib/reverse.js`) on paikallista, ilmaista base64/JWT/hex/JSON-purkua evästeen omasta arvosta — ei verkkoliikennettä, ei arvausta siitä mitä palvelin "oikeasti" tekee datalla.

## Miksi valedata on muoto-validia, ei vain satunnaista tekstiä

`lib/lorem.js` generoi peitetyn arvon `lib/reverse.js`:n tunnistaman rakenteen mukaisesti (UUID, GA-asiakastunniste, hex, numeerinen, JSON, base64-JSON, JWT) sen sijaan että se aina tuottaisi geneeristä `lorem-ipsum-...`-tekstiä. Syy: useimmat trackerit tekevät clientillä logiikan *"jos eväste on olemassa JA parsiutuu odotettuun muotoon, käytä sitä — muuten generoi uusi"*. Muotoa rikkova valedata huomataan ja korjataan pois jo seuraavalla sivunlatauksella; muoto-validi (mutta sisällöltään satunnainen) valedata läpäisee tämän tarkistuksen ja säilyy huomattavasti pidempään. Jokainen generaattori on testattu kiertämään takaisin `inspectValue()`:n läpi ja tunnistumaan samaksi muodoksi (ks. `tests/smoke.test.mjs`).

## Rajoitukset (tärkeää)

- **Vain tässä selaimessa/profiilissa.** Ei suojaa muita selaimia, natiivisovelluksia tai muita laitteita.
- **"Tämä sivu" -näkymä ei näe aitoja kolmannen osapuolen seurantaevästeitä.** `chrome.cookies.getAll({url})` palauttaa vain evästeet, joiden Domain-attribuutti täsmää nykyiseen hostiin (eli sivuston oman alidomeeniperheen evästeet) — esim. mainosverkon omalle domainille asetettu eväste ei näy tässä näkymässä, vaikka se latautuisikin upotettuna sivulla. **Koko selain** -skannaus näkee kaikki selaimeen tallennetut evästeet, mutta ei pysty luotettavasti päättelemään mikä sivu minkäkin asetti (se vaatisi erikseen `webRequest`-pohjaisen Set-Cookie-seurannan).
- **Service worker voi nukahtaa.** Chrome voi sammuttaa MV3-taustaprosessin hetkeksi; jatkuva automaattisuoja voi katketa hetkellisesti kunnes laajennos herää seuraavasta tapahtumasta. Manuaalinen "Peitä nyt" toimii aina heti.
- **Tuntematon ≠ turvallinen, mutta ei myöskään enää automaattisesti koskematon.** Ks. [Luokittelupolitiikka](#luokittelupolitiikka-whitelist--blacklist) — tietokannan tunnistamattomat evästeet peitetään oletuksena ellei heuristiikka tunnista niitä toiminnallisiksi. Tämä on tietoinen kompromissi kattavuuden ja väärien positiivisten välillä, ei virhe.
- **Ei suojaa fingerprinting-tekniikoilta** (canvas/WebGL/font-sormenjälki), jotka eivät käytä evästeitä lainkaan. Tämä työkalu ratkaisee vain eväste-pohjaisen seurannan.
- Tietokanta on staattinen snapshot haun hetkeltä — päivitä ajoittain (ks. alla).

## Mobiili (iOS / selaimet ilman laajennostukea)

[`bookmarklet/`](bookmarklet/) sisältää kevyen, manuaalisesti käynnistettävän bookmarklet-version niille selaimille, joissa ei ole laajennosrajapintaa lainkaan (esim. DuckDuckGon iOS-sovellus). Se ei ole täysi portti — `document.cookie`-rajapinta ei näe HttpOnly-evästeitä eikä toimi taustalla automaattisesti — ks. [`bookmarklet/README.md`](bookmarklet/README.md) rajoituksista ja asennusohjeista.

## Tietokannan päivitys

```bash
curl -o third_party/open-cookie-database.csv \
  https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/master/open-cookie-database.csv
python3 scripts/build_cookie_db.py
```

`third_party/local-overrides.csv` (sama CSV-skeema) säilyy koskemattomana upstream-päivityksessä ja sen rivit voittavat nimiristiriidat — lisää sinne omat OSINT-löydöt tähän tiedostoon, älä upstream-tiedostoon.

## Lisenssi

Oma koodi: MIT (ks. `LICENSE`). Evästetietokanta on johdettu Open Cookie Databasesta, Apache-2.0 (ks. `third_party/LICENSE-open-cookie-database`).

## Yksityisyyskäytäntö

[`docs/index.html`](docs/index.html) (suomeksi ja englanniksi) — julkaistuna GitHub Pagesin kautta osoitteessa **https://homey-ap.github.io/cookie-defense/** kun GitHub Pages on kytketty päälle repon asetuksista (Settings → Pages → Source: Deploy from a branch → `main` → `/docs`). Käytetään Chrome Web Store -listauksen pakollisena yksityisyyskäytäntö-linkkinä.

## Roadmap

- [ ] Safari-portti (Safari Web Extension -konversio, `xcrun safari-web-extension-converter`)
- [ ] Firefox-yhteensopivuus (MV3 `browser.*`-nimiavaruus / polyfill)
- [ ] Valinnainen mitmproxy-pohjainen versio, joka kattaa myös muut sovellukset kuin selaimen (vaatii paikallisen CA-sertifikaatin asennuksen macOS-luottamusketjuun)
- [ ] Automaattinen tietokannan päivitystarkistus
- [ ] `webRequest`-pohjainen Set-Cookie-seuranta, jotta aidot kolmannen osapuolen evästeet voidaan yhdistää siihen sivuun joka ne latasi
- [ ] **GDPR-tietopyyntöluettelon generointi.** Tietokannassa (upstream + `local-overrides.csv`) on jo `Data Controller`- ja `User Privacy & GDPR Rights Portals` -sarakkeet, mutta `build_cookie_db.py` ei tällä hetkellä säilytä niitä JSON-tulosteessa. Laajennus voisi tunnistettujen trackerien perusteella generoida ladattavan tekstitiedoston, jossa jokaiselle yritykselle valmis Art. 15 -tietopyyntöteksti (mitä dataa, mihin tarkoitukseen, kenelle jaettu, säilytysaika + valinnainen Art. 17 -poistopyyntö) ja linkki yrityksen omaan GDPR-portaaliin. **Ei automaattista lähetystä** — identiteetin vahvistus ja lähetyspäätös jäävät tarkoituksella käyttäjälle, koska botin ajama massalähetys kymmenille yrityksille paljastaisi käyttäjän henkilöllisyyden laajemmin kuin on tarkoitus, ja moni portaali muutenkin hylkii ilmeisen automatisoidut pyynnöt.
