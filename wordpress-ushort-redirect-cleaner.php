<?php
/**
 * ushort Redirect Cleaner
 *
 * Wizard zur Sichtung und Bereinigung von Datenbank-Redirect-Injektionen in WordPress,
 * z. B. vorangestellte <meta refresh>/<script>-Weiterleitungen auf ushort.*-Domains.
 *
 * - Ablage im WordPress-Root (neben wp-config.php), Aufruf im Browser.
 * - wp-config.php wird nur gelesen (Tokenizer), NICHT ausgeführt: WordPress und
 *   eventuell infizierte Plugins/Themes werden nicht geladen.
 * - Alle Änderungen laufen in einer Transaktion, Originalwerte landen in einer Backup-Tabelle.
 * - Logs werden nur in der PHP-Session gehalten; zum Abschluss löscht sich die Datei selbst.
 *
 * @package   wordpress-ushort-redirect-cleaner
 * @version   1.0.0
 * @author    Nils Zimmermann, saltylemon Online-Marketing GmbH
 * @link      https://www.saltylemon.de/webentwicklung/wordpress
 * @license   MIT
 */

// ============================================================================
// KONFIGURATION – vor dem Hochladen anpassen
// ============================================================================

// Pflicht: eigener Zugangsschlüssel, mindestens 16 Zeichen. Ohne Schlüssel startet der Wizard nicht.
// Beispiel erzeugen:  php -r "echo bin2hex(random_bytes(16));"
const WPRC_ACCESS_KEY = '';

// Optional: Zugriff nur von diesen IP-Adressen erlauben, z. B. ['203.0.113.10'].
const WPRC_ALLOWED_IPS = [];

// ============================================================================

const WPRC_VERSION = '1.0.0';
const WPRC_BRAND = 'saltylemon Online-Marketing GmbH';
const WPRC_BRAND_URL = 'https://www.saltylemon.de/webentwicklung/wordpress';
const WPRC_AUTHOR = 'Nils Zimmermann';
const WPRC_STEPS = [1 => 'Sichtung', 2 => 'Recherche', 3 => 'Home-URL', 4 => 'Optionen', 5 => 'Ausführen', 6 => 'Abschluss'];

error_reporting(E_ALL);
ini_set('display_errors', '0');

if (PHP_VERSION_ID < 70400) {
	http_response_code(500);
	exit('ushort Redirect Cleaner benötigt PHP 7.4 oder neuer. / ushort Redirect Cleaner requires PHP 7.4 or newer.');
}

header('Content-Type: text/html; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

// ============================================================================
// Hilfsfunktionen
// ============================================================================

function h($s): string
{
	return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function wprc_is_https(): bool
{
	return (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
		|| strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https'
		|| (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
}

/** Protokolleintrag: Textschlüssel und Werte speichern, übersetzt wird erst bei der Ausgabe. */
function wprc_log(string $key, array $args = [], string $level = 'info'): void
{
	$_SESSION['log'][] = [date('Y-m-d H:i:s'), $level, $key, $args];
}

/** Protokoll in der aktuellen Sprache. */
function wprc_log_lines(): array
{
	$lines = [];
	foreach ($_SESSION['log'] ?? [] as $e) {
		$lines[] = '[' . $e[0] . '] ' . strtoupper((string) $e[1]) . '  ' . wprc_t((string) $e[2], ...array_values((array) ($e[3] ?? [])));
	}
	return $lines;
}

function wprc_url(array $q = []): string
{
	$self = strtok((string) ($_SERVER['REQUEST_URI'] ?? ''), '?') ?: basename(__FILE__);
	return $q ? $self . '?' . http_build_query($q) : $self;
}

function wprc_redirect(array $q): void
{
	header('Location: ' . wprc_url($q), true, 303);
	exit;
}

function wprc_flash(string $key, array $args = [], string $type = 'ok'): void
{
	$_SESSION['flash'][] = [$type, $key, $args];
}

/** Host normalisieren: Kleinbuchstaben, ohne "www.". */
function wprc_norm_host(string $host): string
{
	$host = strtolower(trim($host, " .\t\n\r"));
	return strpos($host, 'www.') === 0 ? substr($host, 4) : $host;
}

function wprc_host_of(string $url): string
{
	if (strpos($url, '//') === 0) {
		$url = 'https:' . $url;
	}
	return wprc_norm_host((string) (parse_url($url, PHP_URL_HOST) ?: ''));
}

function wprc_like(string $s): string
{
	return '%' . addcslashes($s, '\\%_') . '%';
}

/** Prepared Statement mit String-Parametern ausführen. */
function wprc_q(mysqli $db, string $sql, array $params = []): mysqli_stmt
{
	$st = $db->prepare($sql);
	if ($params) {
		$params = array_values(array_map('strval', $params));
		$st->bind_param(str_repeat('s', count($params)), ...$params);
	}
	$st->execute();
	return $st;
}

function wprc_val(mysqli $db, string $sql, array $params = [])
{
	$row = wprc_q($db, $sql, $params)->get_result()->fetch_row();
	return $row ? $row[0] : null;
}

function wprc_table_exists(mysqli $db, string $table): bool
{
	return (int) wprc_val($db, 'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [$table]) > 0;
}

/** Text-Spalten einer Tabelle (char/text), optional mit Ausschlussliste. */
function wprc_text_columns(mysqli $db, string $table, array $exclude = []): array
{
	$cols = [];
	$res = $db->query("SHOW COLUMNS FROM `{$table}`");
	while ($c = $res->fetch_assoc()) {
		if (preg_match('~char|text~i', $c['Type']) && !in_array($c['Field'], $exclude, true)) {
			$cols[] = $c['Field'];
		}
	}
	return $cols;
}

function wprc_option(mysqli $db, string $p, string $name): ?string
{
	$v = wprc_val($db, "SELECT option_value FROM `{$p}options` WHERE option_name = ? LIMIT 1", [$name]);
	return $v === null ? null : (string) $v;
}

/** Plugin-Version aus dem Datei-Header lesen, ohne PHP auszuführen. */
function wprc_plugin_version(string $file): ?string
{
	if (!is_file($file) || !is_readable($file)) {
		return null;
	}
	$head = (string) file_get_contents($file, false, null, 0, 8192);
	return preg_match('~^[ \t/*#@]*Version:\s*(\S+)~mi', $head, $m) ? $m[1] : null;
}

// ============================================================================
// wp-config.php lesen (ohne Ausführung)
// ============================================================================

function wprc_find_config(): ?string
{
	if (is_file(__DIR__ . '/wp-config.php')) {
		return __DIR__ . '/wp-config.php';
	}
	// WordPress erlaubt wp-config.php eine Ebene höher, sofern dort keine eigene Installation liegt.
	$up = dirname(__DIR__);
	if (is_file($up . '/wp-config.php') && !is_file($up . '/wp-settings.php')) {
		return $up . '/wp-config.php';
	}
	return null;
}

/** Token-Literal in PHP-Wert umwandeln; null bei nicht statisch auswertbaren Ausdrücken. */
function wprc_token_value($tok, &$ok)
{
	$ok = true;
	if (is_array($tok)) {
		if ($tok[0] === T_CONSTANT_ENCAPSED_STRING) {
			$q = $tok[1][0];
			$s = substr($tok[1], 1, -1);
			if ($q === "'") {
				return str_replace(["\\\\", "\\'"], ["\\", "'"], $s);
			}
			if (strpos($s, '$') !== false) {
				$ok = false;
				return null;
			}
			return stripcslashes($s);
		}
		if ($tok[0] === T_LNUMBER) {
			return (int) $tok[1];
		}
		if ($tok[0] === T_STRING) {
			$l = strtolower($tok[1]);
			if ($l === 'true' || $l === 'false') {
				return $l === 'true';
			}
			if ($l === 'null') {
				return null;
			}
		}
	}
	$ok = false;
	return null;
}

function wprc_parse_config(string $file): array
{
	$tokens = token_get_all((string) file_get_contents($file));
	$t = array_values(array_filter($tokens, function ($x) {
		return !is_array($x) || !in_array($x[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
	}));
	$consts = [];
	$prefix = null;
	$n = count($t);
	for ($i = 0; $i < $n; $i++) {
		$tok = $t[$i];
		if (is_array($tok) && $tok[0] === T_STRING && strtolower($tok[1]) === 'define' && ($t[$i + 1] ?? null) === '('
			&& is_array($t[$i + 2] ?? null) && $t[$i + 2][0] === T_CONSTANT_ENCAPSED_STRING && ($t[$i + 3] ?? null) === ',') {
			$name = wprc_token_value($t[$i + 2], $ok);
			$val = wprc_token_value($t[$i + 4] ?? null, $ok2);
			$end = $t[$i + 5] ?? null;
			if ($ok && $ok2 && ($end === ')' || $end === ',') && !array_key_exists($name, $consts)) {
				$consts[$name] = $val;
			}
		}
		if (is_array($tok) && $tok[0] === T_VARIABLE && $tok[1] === '$table_prefix' && ($t[$i + 1] ?? null) === '=') {
			$val = wprc_token_value($t[$i + 2] ?? null, $ok);
			if ($ok && is_string($val)) {
				$prefix = $val;
			}
		}
	}
	return ['consts' => $consts, 'prefix' => $prefix];
}

/** DB_HOST wie WordPress zerlegen: host, host:port, host:/socket, [ipv6]:port. */
function wprc_parse_host(string $h): array
{
	$host = $h;
	$port = null;
	$socket = null;
	if (($pos = strpos($h, ':/')) !== false) {
		$host = substr($h, 0, $pos);
		$socket = substr($h, $pos + 1);
	} elseif (preg_match('~^\[([^\]]+)\](?::(\d+))?$~', $h, $m)) {
		$host = $m[1];
		$port = isset($m[2]) ? (int) $m[2] : null;
	} elseif (substr_count($h, ':') === 1) {
		[$host, $p] = explode(':', $h);
		$port = $p !== '' ? (int) $p : null;
	}
	return [$host === '' ? 'localhost' : $host, $port, $socket];
}

/** DB-Zugang ermitteln: wp-config.php oder manuelle Eingabe (Session). */
function wprc_db_settings(): array
{
	$cfg = ['source' => null, 'file' => null, 'consts' => [], 'prefix' => null, 'missing' => []];
	if (!empty($_SESSION['manual_db'])) {
		$m = $_SESSION['manual_db'];
		$cfg['source'] = 'manuell';
		$cfg['consts'] = ['DB_NAME' => $m['name'], 'DB_USER' => $m['user'], 'DB_PASSWORD' => $m['pass'], 'DB_HOST' => $m['host'], 'DB_CHARSET' => 'utf8mb4'];
		$cfg['prefix'] = $m['prefix'];
		return $cfg;
	}
	$file = wprc_find_config();
	if (!$file) {
		$cfg['missing'][] = 'wp-config.php';
		return $cfg;
	}
	$parsed = wprc_parse_config($file);
	$cfg['source'] = 'wp-config.php';
	$cfg['file'] = $file;
	$cfg['consts'] = $parsed['consts'];
	$cfg['prefix'] = $parsed['prefix'];
	foreach (['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST'] as $k) {
		if (!array_key_exists($k, $cfg['consts'])) {
			$cfg['missing'][] = $k;
		}
	}
	if ($cfg['prefix'] === null) {
		$cfg['missing'][] = '$table_prefix';
	}
	return $cfg;
}

function wprc_connect(array $cfg): mysqli
{
	mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
	[$host, $port, $socket] = wprc_parse_host((string) $cfg['consts']['DB_HOST']);
	$db = mysqli_init();
	$db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10);
	$db->real_connect($host, (string) $cfg['consts']['DB_USER'], (string) $cfg['consts']['DB_PASSWORD'], (string) $cfg['consts']['DB_NAME'], $port, $socket);
	$charset = (string) ($cfg['consts']['DB_CHARSET'] ?? 'utf8mb4');
	$db->set_charset($charset !== '' ? $charset : 'utf8mb4');
	return $db;
}

// ============================================================================
// Erkennung
// ============================================================================

/** Vertrauenswürdige Hosts: aktueller Host, WP_HOME/WP_SITEURL, gewählte Home-URL. */
function wprc_trusted_hosts(array $consts): array
{
	$hosts = [wprc_norm_host((string) preg_replace('~:\d+$~', '', (string) ($_SERVER['HTTP_HOST'] ?? '')))];
	foreach (['WP_HOME', 'WP_SITEURL'] as $c) {
		if (!empty($consts[$c]) && is_string($consts[$c])) {
			$hosts[] = wprc_host_of($consts[$c]);
		}
	}
	if (!empty($_SESSION['home_url'])) {
		$hosts[] = wprc_host_of($_SESSION['home_url']);
	}
	return array_values(array_unique(array_filter($hosts)));
}

/** Absolute URLs mit fremdem Host aus einem Codefragment ziehen. */
function wprc_foreign_urls(string $code, array $trusted): array
{
	preg_match_all('~(?:https?:)?//[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?::\d+)?(?:/[^\s"\'<>()\\\\;]*)?~i', $code, $m);
	$out = [];
	foreach ($m[0] as $u) {
		$u = rtrim($u, '/.,');
		$host = wprc_host_of($u);
		if ($host !== '' && !in_array($host, $trusted, true)) {
			$out[] = $u;
		}
	}
	return array_values(array_unique($out));
}

/**
 * Prüft, ob ein Inhalt mit einem injizierten Redirect beginnt.
 * Erkannt werden <meta http-equiv="refresh"> und/oder <script>…</script> direkt am Anfang,
 * sofern sie auf einen fremden Host zeigen. Ein direkt folgender Zeilenumbruch gehört zum Payload.
 */
function wprc_extract_payload(string $content, array $trusted): ?array
{
	$pos = 0;
	$payload = '';
	$urls = [];
	if (preg_match('~\s*<meta\s[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*>~iA', $content, $m, 0, $pos)) {
		$u = wprc_foreign_urls($m[0], $trusted);
		if (!$u) {
			return null;
		}
		$payload .= $m[0];
		$pos += strlen($m[0]);
		$urls = array_merge($urls, $u);
	}
	if (preg_match('~\s*<script\b[^>]*>.*?</script>~isA', $content, $m, 0, $pos)) {
		$u = wprc_foreign_urls($m[0], $trusted);
		$redirects = preg_match('~location|window\.open|http-equiv|document\.write~i', $m[0]);
		if ($u && $redirects) {
			$payload .= $m[0];
			$pos += strlen($m[0]);
			$urls = array_merge($urls, $u);
		}
	}
	if ($payload === '') {
		return null;
	}
	if (preg_match('~\r?\n~A', $content, $m, 0, $pos)) {
		$payload .= $m[0];
	}
	return ['payload' => $payload, 'urls' => array_values(array_unique($urls))];
}

function wprc_scan(mysqli $db, string $p, array $trusted, array $extra_hosts = []): array
{
	$r = ['payloads' => [], 'urls' => [], 'hosts' => [], 'infected' => 0, 'occurrences' => [], 'core' => [], 'yoast' => []];

	$res = $db->query("SELECT ID, post_type, post_status, post_title, LEFT(post_content, 20000) AS head
		FROM `{$p}posts` WHERE LEFT(post_content, 300) REGEXP '^[[:space:]]*<(meta|script)'");
	while ($row = $res->fetch_assoc()) {
		$hit = wprc_extract_payload((string) $row['head'], $trusted);
		if (!$hit) {
			continue;
		}
		$k = sha1($hit['payload']);
		if (!isset($r['payloads'][$k])) {
			$r['payloads'][$k] = ['payload' => $hit['payload'], 'urls' => $hit['urls'], 'count' => 0, 'types' => [], 'samples' => []];
		}
		$r['payloads'][$k]['count']++;
		$type = $row['post_type'] . ' / ' . $row['post_status'];
		$r['payloads'][$k]['types'][$type] = ($r['payloads'][$k]['types'][$type] ?? 0) + 1;
		if ($row['post_type'] !== 'revision' && count($r['payloads'][$k]['samples']) < 6) {
			$r['payloads'][$k]['samples'][] = '#' . $row['ID'] . ' ' . ($row['post_title'] !== '' ? $row['post_title'] : wprc_t('(ohne Titel)'));
		}
		$r['infected']++;
		$r['urls'] = array_merge($r['urls'], $hit['urls']);
	}
	$r['urls'] = array_values(array_unique($r['urls']));
	usort($r['urls'], function ($a, $b) {
		return strlen($b) - strlen($a);
	});
	$hosts = array_map('wprc_host_of', $r['urls']);
	foreach ($extra_hosts as $eh) {
		$hosts[] = wprc_norm_host($eh);
	}
	$r['hosts'] = array_values(array_unique(array_filter($hosts)));

	// Kern-URLs
	foreach (['home', 'siteurl'] as $name) {
		$v = (string) wprc_option($db, $p, $name);
		$host = wprc_host_of($v);
		$r['core'][$name] = ['value' => $v, 'malicious' => in_array($host, $r['hosts'], true), 'untrusted' => !in_array($host, $trusted, true)];
	}

	// Yoast SEO
	$active = @unserialize((string) wprc_option($db, $p, 'active_plugins'), ['allowed_classes' => false]);
	$active = is_array($active) ? $active : [];
	$y = [
		'active' => (bool) array_filter($active, function ($pl) {
			return (bool) preg_match('~^wordpress-seo(-premium)?/~', (string) $pl);
		}),
		'option' => wprc_option($db, $p, 'wpseo') !== null,
		'table' => wprc_table_exists($db, $p . 'yoast_indexable'),
		'home_url' => null,
		'home_url_malicious' => false,
		'indexables' => 0,
	];
	if ($y['option']) {
		$o = @unserialize((string) wprc_option($db, $p, 'wpseo'), ['allowed_classes' => false]);
		if (is_array($o) && isset($o['home_url'])) {
			$y['home_url'] = (string) $o['home_url'];
			$y['home_url_malicious'] = in_array(wprc_host_of($y['home_url']), $r['hosts'], true);
		}
	}
	$y['present'] = $y['active'] || $y['option'] || $y['table'];
	$r['yoast'] = $y;

	// Weitere Vorkommen der Schad-Hosts (nur Bericht)
	$y_cols = $y['table'] ? wprc_text_columns($db, $p . 'yoast_indexable', ['permalink_hash']) : [];
	foreach ($r['hosts'] as $host) {
		$like = wprc_like($host);
		$o = [];
		$o['posts_total'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}posts` WHERE post_content LIKE ? OR post_excerpt LIKE ? OR guid LIKE ?", [$like, $like, $like]);
		$o['postmeta'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}postmeta` WHERE meta_value LIKE ?", [$like]);
		$o['comments'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}comments` WHERE comment_content LIKE ? OR comment_author_url LIKE ?", [$like, $like]);
		$o['users'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}users` WHERE user_url LIKE ?", [$like]);
		$names = [];
		$st = wprc_q($db, "SELECT option_name FROM `{$p}options` WHERE option_value LIKE ? LIMIT 50", [$like])->get_result();
		while ($row = $st->fetch_row()) {
			$names[] = $row[0];
		}
		$o['options'] = $names;
		if ($y_cols) {
			$where = implode(' OR ', array_map(function ($c) {
				return "`{$c}` LIKE ?";
			}, $y_cols));
			$o['yoast_indexable'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}yoast_indexable` WHERE {$where}", array_fill(0, count($y_cols), $like));
			$r['yoast']['indexables'] += $o['yoast_indexable'];
		}
		$r['occurrences'][$host] = $o;
	}
	return $r;
}

/** Zusätzliche, nur lesende Prüfpunkte zum Vorfall. */
function wprc_health(mysqli $db, string $p, array $consts): array
{
	$out = [];
	$out['mysql'] = (string) wprc_val($db, 'SELECT VERSION()');
	$vfile = __DIR__ . '/wp-includes/version.php';
	$out['wp'] = (is_file($vfile) && preg_match('~\$wp_version\s*=\s*[\'"]([^\'"]+)~', (string) file_get_contents($vfile), $m)) ? $m[1] : null;

	$content = (!empty($consts['WP_CONTENT_DIR']) && is_string($consts['WP_CONTENT_DIR'])) ? $consts['WP_CONTENT_DIR'] : __DIR__ . '/wp-content';
	$out['updraft'] = wprc_plugin_version($content . '/plugins/updraftplus/updraftplus.php');
	$out['udc_keys'] = wprc_option($db, $p, 'updraft_central_localkeys') !== null;
	$out['udc_log'] = wprc_option($db, $p, 'updraftcentral_client_log') !== null;
	$mu = is_dir($content . '/mu-plugins') ? array_values(array_diff(scandir($content . '/mu-plugins') ?: [], ['.', '..', 'index.php'])) : [];
	$dropins = array_values(array_filter(['advanced-cache.php', 'object-cache.php', 'db.php', 'sunrise.php', 'maintenance.php'], function ($f) use ($content) {
		return is_file($content . '/' . $f);
	}));
	$out['mu'] = $mu;
	$out['dropins'] = $dropins;

	$admins = [];
	$like = '%' . addcslashes('"administrator"', '\\%_') . '%';
	$st = wprc_q($db, "SELECT u.ID, u.user_login, u.user_email, u.user_registered FROM `{$p}users` u
		JOIN `{$p}usermeta` m ON m.user_id = u.ID AND m.meta_key = ? WHERE m.meta_value LIKE ? ORDER BY u.user_registered", [$p . 'capabilities', $like])->get_result();
	while ($row = $st->fetch_assoc()) {
		$admins[] = $row;
	}
	$out['admins'] = $admins;
	$out['new_users'] = (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}users` WHERE user_registered >= (NOW() - INTERVAL 30 DAY)");

	$engines = [];
	$st = wprc_q($db, 'SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?, ?, ?)',
		[$p . 'posts', $p . 'options', $p . 'postmeta', $p . 'yoast_indexable'])->get_result();
	while ($row = $st->fetch_row()) {
		$engines[$row[0]] = $row[1];
	}
	$out['engines'] = $engines;
	return $out;
}

// ============================================================================
// Recherche
// ============================================================================

function wprc_dns(string $host): array
{
	$host = trim($host, '[]');
	if (filter_var($host, FILTER_VALIDATE_IP)) {
		return [$host];
	}
	$ips = [];
	if (function_exists('dns_get_record')) {
		foreach ((array) @dns_get_record($host, DNS_A + DNS_AAAA) as $rec) {
			$ips[] = $rec['ip'] ?? ($rec['ipv6'] ?? null);
		}
	}
	if (!$ips) {
		$ips = @gethostbynamel($host) ?: [];
	}
	return array_values(array_unique(array_filter($ips)));
}

/** Weiterleitungskette per HEAD abrufen (ohne Body, keine privaten Ziel-IPs). */
function wprc_resolve_chain(string $url, int $max = 6): array
{
	$hops = [];
	for ($i = 0; $i < $max; $i++) {
		if (strpos($url, '//') === 0) {
			$url = 'https:' . $url;
		}
		$parts = parse_url($url);
		$scheme = strtolower((string) ($parts['scheme'] ?? ''));
		$host = (string) ($parts['host'] ?? '');
		if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
			$hops[] = ['url' => $url, 'error' => wprc_t('Keine gültige http(s)-URL')];
			break;
		}
		$ips = wprc_dns($host);
		$public = array_values(array_filter($ips, function ($ip) {
			return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
		}));
		if (!$ips) {
			$hops[] = ['url' => $url, 'error' => wprc_t('DNS-Auflösung fehlgeschlagen')];
			break;
		}
		if (count($public) !== count($ips)) {
			$hops[] = ['url' => $url, 'error' => wprc_t('Ziel zeigt auf private/reservierte IP – abgebrochen')];
			break;
		}
		$status = null;
		$location = null;
		$server = null;
		$error = null;
		if (function_exists('curl_init')) {
			$port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
			$ch = curl_init($url);
			curl_setopt_array($ch, [
				CURLOPT_NOBODY => true,
				CURLOPT_HEADER => true,
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_TIMEOUT => 8,
				CURLOPT_CONNECTTIMEOUT => 5,
				CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
				CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $public[0]],
				CURLOPT_USERAGENT => 'Mozilla/5.0 (Linux; Android 14; Mobile) ushort-Redirect-Cleaner/' . WPRC_VERSION,
			]);
			$raw = curl_exec($ch);
			if ($raw === false) {
				$error = curl_error($ch);
			} else {
				$status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
				if (preg_match('~^location:\s*(\S+)~mi', (string) $raw, $m)) {
					$location = $m[1];
				}
				if (preg_match('~^server:\s*(.+)$~mi', (string) $raw, $m)) {
					$server = trim($m[1]);
				}
			}
			curl_close($ch);
		} elseif (ini_get('allow_url_fopen')) {
			$ctx = stream_context_create(['http' => ['method' => 'HEAD', 'follow_location' => 0, 'max_redirects' => 0, 'timeout' => 8, 'ignore_errors' => true,
				'user_agent' => 'Mozilla/5.0 (Linux; Android 14; Mobile) ushort-Redirect-Cleaner/' . WPRC_VERSION]]);
			@file_get_contents($url, false, $ctx);
			$headers = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?: []) : ($http_response_header ?? []);
			foreach ($headers as $line) {
				if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) {
					$status = (int) $m[1];
				} elseif (preg_match('~^location:\s*(\S+)~i', $line, $m)) {
					$location = $m[1];
				} elseif (preg_match('~^server:\s*(.+)$~i', $line, $m)) {
					$server = trim($m[1]);
				}
			}
			if ($status === null) {
				$error = wprc_t('Keine Antwort');
			}
		} else {
			$error = wprc_t('Weder cURL noch allow_url_fopen verfügbar');
		}
		$hops[] = ['url' => $url, 'ip' => $public[0], 'status' => $status, 'location' => $location, 'server' => $server, 'error' => $error];
		if ($error || !$location || $status < 300 || $status >= 400) {
			break;
		}
		// relative Location auflösen
		if (!preg_match('~^https?://~i', $location)) {
			$location = $scheme . '://' . $host . (isset($parts['port']) ? ':' . $parts['port'] : '') . '/' . ltrim($location, '/');
		}
		$url = $location;
	}
	return $hops;
}

function wprc_lookup_links(string $url): array
{
	$host = wprc_host_of($url);
	return [
		'VirusTotal' => 'https://www.virustotal.com/gui/domain/' . rawurlencode($host),
		'urlscan.io' => 'https://urlscan.io/search/#' . rawurlencode('domain:' . $host),
		'URLhaus' => 'https://urlhaus.abuse.ch/browse.php?search=' . rawurlencode($host),
		'Google Safe Browsing' => 'https://transparencyreport.google.com/safe-browsing/search?url=' . rawurlencode($host),
		'Whois' => 'https://who.is/whois/' . rawurlencode($host),
	];
}

// ============================================================================
// Home-URL
// ============================================================================

function wprc_home_candidates(array $consts, array $scan): array
{
	$c = [];
	foreach (['WP_HOME' => 'WP_HOME (wp-config.php)', 'WP_SITEURL' => 'WP_SITEURL (wp-config.php)'] as $k => $label) {
		if (!empty($consts[$k]) && is_string($consts[$k])) {
			$c[$label] = rtrim($consts[$k], '/');
		}
	}
	foreach (['home' => wprc_t('Option „home“ (Datenbank)'), 'siteurl' => wprc_t('Option „siteurl“ (Datenbank)')] as $k => $label) {
		$v = $scan['core'][$k] ?? null;
		if ($v && $v['value'] !== '' && !$v['malicious']) {
			$c[$label] = rtrim($v['value'], '/');
		}
	}
	if (!empty($scan['yoast']['home_url']) && !$scan['yoast']['home_url_malicious']) {
		$c[wprc_t('Yoast-Cache (wpseo.home_url)')] = rtrim($scan['yoast']['home_url'], '/');
	}
	$host = (string) ($_SERVER['HTTP_HOST'] ?? '');
	if ($host !== '') {
		$path = rtrim(str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
		$c[wprc_t('Aktueller Aufruf (Server)')] = (wprc_is_https() ? 'https' : 'http') . '://' . $host . $path;
	}
	$unique = [];
	foreach ($c as $label => $url) {
		if (!in_array($url, $unique, true)) {
			$unique[$label] = $url;
		}
	}
	return $unique;
}

function wprc_validate_home(string $url, array $bad_hosts): ?string
{
	$url = rtrim(trim($url), '/');
	if (!filter_var($url, FILTER_VALIDATE_URL)) {
		return null;
	}
	$p = parse_url($url);
	if (!in_array(strtolower((string) ($p['scheme'] ?? '')), ['http', 'https'], true) || empty($p['host']) || isset($p['query']) || isset($p['fragment']) || isset($p['user'])) {
		return null;
	}
	if (in_array(wprc_norm_host($p['host']), $bad_hosts, true)) {
		return null;
	}
	return $url;
}

// ============================================================================
// Bereinigung
// ============================================================================

function wprc_backup_row(mysqli $db, string $p, string $run, string $tbl, string $pk, string $col, ?string $original): void
{
	wprc_q($db, "INSERT INTO `{$p}wprc_backup` (run_id, tbl, pk, col, original, created_at) VALUES (?, ?, ?, ?, ?, NOW())", [$run, $tbl, $pk, $col, (string) $original]);
}

function wprc_run(mysqli $db, string $p, array $scan, array $opt, string $home): array
{
	$run = date('YmdHis') . '-' . bin2hex(random_bytes(3));
	$stats = ['run' => $run, 'posts' => 0, 'core' => 0, 'wpseo' => 0, 'indexables' => 0, 'revisions' => 0];
	$backup = !empty($opt['backup']);

	if ($backup) {
		// Collation von wp_options übernehmen, damit Joins bei der Wiederherstellung nicht an
		// abweichenden Server-Standards (z. B. utf8mb4_0900_ai_ci) scheitern.
		$coll = (string) wprc_val($db, 'SELECT TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [$p . 'options']);
		$coll = preg_match('~^[a-z0-9]+_[a-z0-9_]+$~i', $coll) ? $coll : 'utf8mb4_unicode_ci';
		$charset = explode('_', $coll)[0];
		// DDL vor der Transaktion (CREATE TABLE erzwingt in MySQL einen impliziten Commit).
		$db->query("CREATE TABLE IF NOT EXISTS `{$p}wprc_backup` (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
			run_id VARCHAR(32) NOT NULL, tbl VARCHAR(64) NOT NULL, pk VARCHAR(191) NOT NULL,
			col VARCHAR(64) NOT NULL, original LONGTEXT, created_at DATETIME NOT NULL,
			KEY run_id (run_id)
		) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$coll}");
		wprc_log('Backup-Tabelle %s bereit (Lauf %s).', [$p . 'wprc_backup', $run]);
	}

	$db->begin_transaction();
	try {
		// 1. Payload am Anfang von post_content entfernen (exakter Byte-Vergleich)
		foreach ($opt['payloads'] as $hash) {
			if (!isset($scan['payloads'][$hash])) {
				continue;
			}
			$pl = $scan['payloads'][$hash]['payload'];
			$where = 'CAST(LEFT(post_content, CHAR_LENGTH(?)) AS BINARY) = CAST(? AS BINARY)';
			if ($backup) {
				wprc_q($db, "INSERT INTO `{$p}wprc_backup` (run_id, tbl, pk, col, original, created_at)
					SELECT ?, 'posts', ID, 'post_content', post_content, NOW() FROM `{$p}posts` WHERE {$where}", [$run, $pl, $pl]);
			}
			$n = wprc_q($db, "UPDATE `{$p}posts` SET post_content = SUBSTRING(post_content, CHAR_LENGTH(?) + 1) WHERE {$where}", [$pl, $pl, $pl])->affected_rows;
			$stats['posts'] += $n;
			wprc_log('Payload %s: %d Einträge in %s bereinigt.', [substr($hash, 0, 10), $n, $p . 'posts']);
		}

		// 2. home/siteurl
		if (!empty($opt['core'])) {
			foreach (['home', 'siteurl'] as $name) {
				if (!empty($scan['core'][$name]['malicious'])) {
					if ($backup) {
						wprc_backup_row($db, $p, $run, 'options', $name, 'option_value', $scan['core'][$name]['value']);
					}
					$stats['core'] += wprc_q($db, "UPDATE `{$p}options` SET option_value = ? WHERE option_name = ?", [$home, $name])->affected_rows;
					wprc_log('Option %s: „%s“ → „%s“.', [$name, $scan['core'][$name]['value'], $home]);
				}
			}
		}

		// 3. Yoast SEO
		if (!empty($opt['yoast']) && $scan['yoast']['present']) {
			$raw = wprc_option($db, $p, 'wpseo');
			$o = $raw !== null ? @unserialize($raw, ['allowed_classes' => false]) : false;
			if (is_array($o) && isset($o['home_url']) && in_array(wprc_host_of((string) $o['home_url']), $scan['hosts'], true)) {
				if ($backup) {
					wprc_backup_row($db, $p, $run, 'options', 'wpseo', 'option_value', $raw);
				}
				$old = $o['home_url'];
				$o['home_url'] = $home;
				$stats['wpseo'] = wprc_q($db, "UPDATE `{$p}options` SET option_value = ? WHERE option_name = 'wpseo'", [serialize($o)])->affected_rows;
				wprc_log('Yoast wpseo.home_url: „%s“ → „%s“.', [$old, $home]);
			}
			if ($scan['yoast']['table']) {
				$t = "{$p}yoast_indexable";
				$cols = wprc_text_columns($db, $t, ['permalink_hash']);
				$ids = [];
				foreach ($scan['urls'] as $bad) {
					foreach ($cols as $col) {
						$like = wprc_like($bad);
						$st = wprc_q($db, "SELECT id, `{$col}` FROM `{$t}` WHERE `{$col}` LIKE ?", [$like])->get_result();
						while ($row = $st->fetch_row()) {
							$ids[(int) $row[0]] = true;
							if ($backup) {
								wprc_backup_row($db, $p, $run, 'yoast_indexable', (string) $row[0], $col, $row[1]);
							}
						}
						$n = wprc_q($db, "UPDATE `{$t}` SET `{$col}` = REPLACE(`{$col}`, ?, ?) WHERE `{$col}` LIKE ?", [$bad, $home, $like])->affected_rows;
						if ($n) {
							$stats['indexables'] += $n;
							wprc_log('Yoast-Indexables: %d× „%s“ in Spalte %s ersetzt.', [$n, $bad, $col]);
						}
					}
				}
				if ($ids) {
					// Yoast-Format: strlen($permalink) . ':' . md5($permalink) – Länge in Bytes
					$in = implode(',', array_map('intval', array_keys($ids)));
					$db->query("UPDATE `{$t}` SET permalink_hash = CONCAT(LENGTH(permalink), ':', MD5(permalink)) WHERE permalink IS NOT NULL AND id IN ({$in})");
					wprc_log('Yoast permalink_hash für %d Indexables neu berechnet.', [count($ids)]);
				}
			}
		}

		// 4. Revisionen löschen (optional)
		if (!empty($opt['revisions'])) {
			$db->query("DELETE pm FROM `{$p}postmeta` pm JOIN `{$p}posts` po ON po.ID = pm.post_id WHERE po.post_type = 'revision'");
			$db->query("DELETE FROM `{$p}posts` WHERE post_type = 'revision'");
			$stats['revisions'] = $db->affected_rows;
			wprc_log('%d Revisionen gelöscht.', [$stats['revisions']]);
		}

		$db->commit();
		wprc_log('Transaktion abgeschlossen (COMMIT).', [], 'ok');
	} catch (Throwable $e) {
		$db->rollback();
		wprc_log('Fehler, alle Änderungen zurückgerollt: %s', [$e->getMessage()], 'error');
		throw $e;
	}
	return $stats;
}

// ============================================================================
// Sprache / Language
// ============================================================================

const WPRC_LANGS = ['de' => 'DE', 'en' => 'EN'];

/** Bevorzugte Browsersprache (Accept-Language): Deutsch → de, alles andere → en. */
function wprc_detect_lang(): string
{
	$best = '';
	$best_q = -1.0;
	foreach (explode(',', (string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')) as $part) {
		$bits = explode(';', trim($part));
		$tag = strtolower(trim($bits[0]));
		if ($tag === '') {
			continue;
		}
		$q = 1.0;
		foreach (array_slice($bits, 1) as $b) {
			if (preg_match('~^\s*q\s*=\s*([0-9.]+)~i', $b, $m)) {
				$q = (float) $m[1];
			}
		}
		if ($q > $best_q) {
			$best_q = $q;
			$best = $tag;
		}
	}
	return preg_match('~^de(-|$)~', $best) ? 'de' : 'en';
}

function wprc_lang(): string
{
	$l = isset($_SESSION['lang']) ? (string) $_SESSION['lang'] : '';
	return array_key_exists($l, WPRC_LANGS) ? $l : wprc_detect_lang();
}

/** Sprachwahl aus ?lang= in die Session übernehmen (nach session_start). */
function wprc_lang_from_request(): void
{
	$l = (string) ($_GET['lang'] ?? '');
	if (array_key_exists($l, WPRC_LANGS)) {
		$_SESSION['lang'] = $l;
	}
}

/** Übersetzen: Der deutsche Text ist der Schlüssel, Platzhalter wie bei sprintf(). */
function wprc_t(string $s, ...$args): string
{
	static $en = null;
	if (wprc_lang() === 'en') {
		$en = $en ?? wprc_en();
		$s = $en[$s] ?? $s;
	}
	return $args ? vsprintf($s, $args) : $s;
}

function wprc_en(): array
{
	return [
		// Navigation & Rahmen
		'Sichtung' => 'Scan',
		'Recherche' => 'Research',
		'Home-URL' => 'Home URL',
		'Optionen' => 'Options',
		'Ausführen' => 'Run',
		'Abschluss' => 'Finish',
		'Sprache' => 'Language',
		'Abmelden' => 'Log out',
		'Entwickelt von %s' => 'Developed by %s',
		'Ohne Gewähr – vorher immer ein vollständiges Backup anlegen.' => 'No warranty – always create a full backup first.',
		'Zurück' => 'Back',
		'ja' => 'yes',
		'nein' => 'no',
		'keine' => 'none',
		'keins' => 'none',
		'vorhanden' => 'present',
		'fehlt' => 'missing',
		'unbekannt' => 'unknown',
		'manuell' => 'manual',

		// Erkennung, Recherche, Bereinigung
		'(ohne Titel)' => '(no title)',
		'Keine gültige http(s)-URL' => 'Not a valid http(s) URL',
		'DNS-Auflösung fehlgeschlagen' => 'DNS resolution failed',
		'Ziel zeigt auf private/reservierte IP – abgebrochen' => 'Target points to a private/reserved IP – aborted',
		'Keine Antwort' => 'No response',
		'Weder cURL noch allow_url_fopen verfügbar' => 'Neither cURL nor allow_url_fopen available',
		'Option „home“ (Datenbank)' => 'Option "home" (database)',
		'Option „siteurl“ (Datenbank)' => 'Option "siteurl" (database)',
		'Yoast-Cache (wpseo.home_url)' => 'Yoast cache (wpseo.home_url)',
		'Aktueller Aufruf (Server)' => 'Current request (server)',
		'Backup-Tabelle %s bereit (Lauf %s).' => 'Backup table %s ready (run %s).',
		'Payload %s: %d Einträge in %s bereinigt.' => 'Payload %s: %d entries cleaned in %s.',
		'Option %s: „%s“ → „%s“.' => 'Option %s: "%s" → "%s".',
		'Yoast wpseo.home_url: „%s“ → „%s“.' => 'Yoast wpseo.home_url: "%s" → "%s".',
		'Yoast-Indexables: %d× „%s“ in Spalte %s ersetzt.' => 'Yoast indexables: replaced "%2$s" %1$d× in column %3$s.',
		'Yoast permalink_hash für %d Indexables neu berechnet.' => 'Yoast permalink_hash recalculated for %d indexables.',
		'%d Revisionen gelöscht.' => '%d revisions deleted.',
		'Transaktion abgeschlossen (COMMIT).' => 'Transaction completed (COMMIT).',
		'Fehler, alle Änderungen zurückgerollt: %s' => 'Error, all changes rolled back: %s',

		// Zusammenfassung des Scans
		'Infizierte Einträge' => 'Infected entries',
		'Payload-Varianten' => 'Payload variants',
		'Schad-Hosts' => 'Malicious hosts',
		'%d Einträge' => '%d entries',
		'Verteilung' => 'Distribution',
		'Beispiele' => 'Examples',

		// Einrichtung, Login, DB
		'Einrichtung erforderlich' => 'Setup required',
		'Der Wizard ist gesperrt, bis in dieser Datei ein Zugangsschlüssel gesetzt ist.' => 'The wizard is locked until an access key is set in this file.',
		'Datei <code>%s</code> lokal öffnen.' => 'Open the file <code>%s</code> locally.',
		'Bei <code>%s</code> einen zufälligen Schlüssel mit mindestens 16 Zeichen eintragen, z.&nbsp;B. <code>%s</code>' => 'Enter a random key of at least 16 characters at <code>%s</code>, e.g. <code>%s</code>',
		'Datei erneut hochladen und diese Seite neu laden.' => 'Upload the file again and reload this page.',
		'Zugriff verweigert.' => 'Access denied.',
		'Anmeldung von %s.' => 'Login from %s.',
		'Zugangsschlüssel falsch.' => 'Wrong access key.',
		'Anmelden' => 'Log in',
		'Zugangsschlüssel (aus <code>WPRC_ACCESS_KEY</code>)' => 'Access key (from <code>WPRC_ACCESS_KEY</code>)',
		'Dieses Werkzeug liest die Zugangsdaten aus der <code>wp-config.php</code> und kann die Datenbank verändern. Nach Abschluss löscht es sich selbst.' => 'This tool reads the credentials from <code>wp-config.php</code> and can modify the database. It deletes itself when finished.',
		'Ungültige Anfrage' => 'Invalid request',
		'Sicherheitstoken ungültig. Bitte Seite neu laden.' => 'Invalid security token. Please reload the page.',
		'Protokoll' => 'Log',
		'Ungültiges Tabellenpräfix.' => 'Invalid table prefix.',
		'Manuelle DB-Zugangsdaten gesetzt (Host %s, DB %s).' => 'Manual database credentials set (host %s, database %s).',
		'Tabellenpräfix enthält unzulässige Zeichen.' => 'Table prefix contains invalid characters.',
		'Tabelle %s nicht gefunden – stimmt das Präfix?' => 'Table %s not found – is the prefix correct?',
		'Verbindung fehlgeschlagen: %s' => 'Connection failed: %s',
		'Aus der wp-config.php konnten nicht alle Werte statisch gelesen werden: %s.' => 'Not all values could be read statically from wp-config.php: %s.',
		'Datenbankverbindung' => 'Database connection',
		'Zugangsdaten bitte manuell eintragen (sie werden nur in der Session gehalten):' => 'Please enter the credentials manually (they are only kept in the session):',
		'Datenbankname' => 'Database name',
		'Benutzer' => 'User',
		'Passwort' => 'Password',
		'Tabellenpräfix' => 'Table prefix',
		'Verbinden' => 'Connect',

		// Aktionen
		'Zusätzliche Such-Hosts: %s' => 'Additional search hosts: %s',
		'Weiterleitungskette abgerufen für %s: %d Station(en).' => 'Redirect chain fetched for %s: %d hop(s).',
		'Ungültige Home-URL. Erlaubt ist http(s)://host[/pfad] ohne Query; Schad-Hosts sind ausgeschlossen.' => 'Invalid home URL. Allowed is http(s)://host[/path] without query; malicious hosts are excluded.',
		'Home-URL festgelegt: %s' => 'Home URL set: %s',
		'Optionen gespeichert: %s' => 'Options saved: %s',
		'Bitte bestätigen, dass ein aktuelles Datenbank-Backup vorliegt.' => 'Please confirm that you have a current database backup.',
		'Home-URL und Optionen fehlen.' => 'Home URL and options are missing.',
		'Bereinigung erfolgreich abgeschlossen.' => 'Cleanup completed successfully.',
		'Fehler: %s – es wurde nichts geändert.' => 'Error: %s – nothing was changed.',
		'Backup-Tabelle %s gelöscht.' => 'Backup table %s deleted.',
		'Session und Protokoll gelöscht.' => 'Session and log deleted.',
		'Skriptdatei %s gelöscht.' => 'Script file %s deleted.',
		'Skriptdatei konnte NICHT gelöscht werden – bitte sofort per FTP/SSH entfernen!' => 'Script file could NOT be deleted – remove it via FTP/SSH immediately!',
		'Fertig' => 'Done',
		'Nächste Schritte' => 'Next steps',
		'Elementor: <em>Werkzeuge → Dateien &amp; Daten regenerieren</em>, Seiten-/Server-Cache leeren.' => 'Elementor: <em>Tools → Regenerate Files &amp; Data</em>, clear page and server caches.',
		'Zugangsdaten ändern: Datenbank, FTP/SFTP/SSH, Hosting-Konto, alle WordPress-Admins; neue Salts in der <code>wp-config.php</code>.' => 'Change credentials: database, FTP/SFTP/SSH, hosting account, all WordPress admins; new salts in <code>wp-config.php</code>.',
		'Einfallstor klären (Server-/FTP-Logs, weitere Installationen im selben Hosting-Konto).' => 'Identify the entry point (server/FTP logs, other installations in the same hosting account).',
		'Seite mobil prüfen (Smartphone bzw. Mobile-Emulation), Google Search Console auf Sicherheitsprobleme prüfen.' => 'Check the site on mobile (smartphone or mobile emulation) and check Google Search Console for security issues.',

		// Schritt 1
		'Nur lesend – in diesem Schritt wird nichts verändert.' => 'Read-only – nothing is changed in this step.',
		'Keine Redirect-Injektion am Anfang von Beitragsinhalten gefunden.' => 'No redirect injection found at the beginning of post content.',
		'Website-URLs' => 'Site URLs',
		'Quelle' => 'Source',
		'Wert' => 'Value',
		'Schad-Host' => 'Malicious host',
		'weicht vom aktuellen Host ab' => 'differs from current host',
		'Plugin aktiv' => 'Plugin active',
		'Tabelle' => 'Table',
		'Gecachte <code>home_url</code>' => 'Cached <code>home_url</code>',
		'Indexables mit Schad-Host' => 'Indexables with malicious host',
		'Weitere Prüfpunkte' => 'Further checks',
		'Konfiguration' => 'Configuration',
		'%s, Präfix <code>%s</code>, DB <code>%s</code>' => '%s, prefix <code>%s</code>, DB <code>%s</code>',
		'Tabellen-Engine' => 'Table engine',
		'nicht InnoDB: %s' => 'not InnoDB: %s',
		' – keine Rollback-Sicherheit, Backup ist Pflicht' => ' – no rollback safety, backup is mandatory',
		'anfällig für CVE-2026-10795' => 'vulnerable to CVE-2026-10795',
		'vor 1.26.13 (UpdraftCentral-Schlüsselvorfall 10/2026)' => 'before 1.26.13 (UpdraftCentral key incident 10/2026)',
		'aktuell genug' => 'recent enough',
		'UpdraftCentral-Schlüssel' => 'UpdraftCentral keys',
		'vorhanden – prüfen/löschen' => 'present – review/delete',
		'vorhanden – auf „Command received“ prüfen' => 'present – check for "Command received"',
		'Must-Use-Plugins' => 'Must-use plugins',
		'Neue Benutzer (30 Tage)' => 'New users (30 days)',
		'Administratoren' => 'Administrators',
		'seit %s' => 'since %s',
		'Weiter: Recherche' => 'Next: Research',

		// Schritt 2
		'Gefundene Schad-URLs mit externen Prüfdiensten abgleichen. Die Links öffnen sich ohne Referrer.' => 'Check the malicious URLs found against external services. Links open without a referrer.',
		'Keine Schad-URLs in Payloads gefunden.' => 'No malicious URLs found in payloads.',
		'keine Auflösung' => 'no resolution',
		'Vorkommen in der DB: Beiträge %d · Postmeta %d · Kommentare %d · Benutzer %d' => 'Occurrences in the DB: posts %d · postmeta %d · comments %d · users %d',
		' · Yoast-Indexables %d' => ' · Yoast indexables %d',
		'Es gibt Vorkommen außerhalb des erkannten Payloads (z.&nbsp;B. Postmeta). Diese werden nicht automatisch bereinigt – bitte manuell prüfen.' => 'There are occurrences outside the detected payload (e.g. postmeta). These are not cleaned automatically – please review them manually.',
		'Weiter nach' => 'Redirects to',
		'Weiterleitungskette abrufen' => 'Fetch redirect chain',
		'HEAD-Request vom Server aus, ohne Inhalte zu laden. Der Betreiber der Domain sieht dabei die Server-IP.' => 'HEAD request from the server, without loading content. The domain operator will see the server IP.',
		'Zusätzliche Domains durchsuchen' => 'Search additional domains',
		'Weitere verdächtige Hosts (kommagetrennt), z.&nbsp;B. bekannte Varianten derselben Kampagne' => 'Further suspicious hosts (comma-separated), e.g. known variants of the same campaign',
		'Suchen' => 'Search',
		'<code>%s</code>: Beiträge %d · Postmeta %d · Optionen %d' => '<code>%s</code>: posts %d · postmeta %d · options %d',
		'Weiter: Home-URL' => 'Next: Home URL',

		// Schritt 3
		'Diese URL ersetzt die Schad-URL in Yoast und (falls betroffen) in <code>home</code>/<code>siteurl</code>. Ohne abschließenden Schrägstrich.' => 'This URL replaces the malicious URL in Yoast and (if affected) in <code>home</code>/<code>siteurl</code>. Without trailing slash.',
		'Manuell eintragen:' => 'Enter manually:',
		'https://www.example.de' => 'https://www.example.com',
		'Übernehmen &amp; weiter' => 'Apply &amp; continue',
		'Bitte zuerst die Home-URL festlegen.' => 'Please set the home URL first.',

		// Schritt 4
		'Beitragsinhalte' => 'Post content',
		'Keine Payloads gefunden.' => 'No payloads found.',
		'Payload <code>%s</code> aus <strong>%d</strong> Einträgen entfernen' => 'Remove payload <code>%s</code> from <strong>%d</strong> entries',
		'<code>%s</code> auf <code>%s</code> setzen' => 'Set <code>%s</code> to <code>%s</code>',
		'Liegt WordPress in einem Unterverzeichnis, <code>siteurl</code> danach manuell prüfen.' => 'If WordPress is installed in a subdirectory, check <code>siteurl</code> manually afterwards.',
		'<code>home</code> und <code>siteurl</code> sind nicht betroffen.' => '<code>home</code> and <code>siteurl</code> are not affected.',
		'Yoast bereinigen: gecachte <code>home_url</code>' => 'Clean Yoast: cached <code>home_url</code>',
		'betroffen' => 'affected',
		' und %d Indexables (inkl. <code>permalink_hash</code>)' => ' and %d indexables (incl. <code>permalink_hash</code>)',
		'Yoast SEO ist nicht installiert – Schritt entfällt.' => 'Yoast SEO is not installed – step skipped.',
		'Weitere Optionen' => 'Further options',
		'Originalwerte in Tabelle <code>%s</code> sichern (empfohlen)' => 'Back up original values in table <code>%s</code> (recommended)',
		'Alle Revisionen löschen (nach der Bereinigung; nicht im Backup enthalten)' => 'Delete all revisions (after cleanup; not included in the backup)',
		'Speichern &amp; weiter' => 'Save &amp; continue',

		// Schritt 5
		'Beitragsinhalte: <strong>%d</strong> Einträge' => 'Post content: <strong>%d</strong> entries',
		'Yoast: <code>home_url</code> %s, %d Indexables' => 'Yoast: <code>home_url</code> %s, %d indexables',
		'ersetzen' => 'replace',
		'unverändert' => 'unchanged',
		'Revisionen löschen: <strong>%d</strong>' => 'Delete revisions: <strong>%d</strong>',
		'Backup-Tabelle: %s' => 'Backup table: %s',
		'Geplante Änderungen' => 'Planned changes',
		'Ersatz-URL: <code>%s</code>' => 'Replacement URL: <code>%s</code>',
		'Ich habe ein aktuelles, vollständiges Datenbank-Backup.' => 'I have a current, complete database backup.',
		'Bereinigung jetzt ausführen' => 'Run cleanup now',

		// Schritt 6
		'Beiträge bereinigt' => 'Posts cleaned',
		'Yoast (Option / Indexables)' => 'Yoast (option / indexables)',
		'Revisionen gelöscht' => 'Revisions deleted',
		'In dieser Session wurde noch keine Bereinigung ausgeführt.' => 'No cleanup has been run in this session yet.',
		'Nachkontrolle' => 'Verification',
		'Erneuter Scan: keine Payloads und keine Vorkommen bekannter Schad-Hosts mehr.' => 'Re-scan: no payloads and no occurrences of known malicious hosts left.',
		'Erneuter Scan: %d Payload-Einträge, %d weitere Vorkommen bekannter Schad-Hosts.' => 'Re-scan: %d payload entries, %d further occurrences of known malicious hosts.',
		'Protokoll herunterladen' => 'Download log',
		'Abschließen' => 'Finish',
		'Backup-Tabelle <code>%s</code> löschen (erst, wenn die Website geprüft ist)' => 'Delete backup table <code>%s</code> (only once the site has been checked)',
		'Bleibt sie bestehen, später entfernen mit: <code>%s</code>' => 'If you keep it, remove it later with: <code>%s</code>',
		'Löscht Protokoll und Session und entfernt <code>%s</code> vom Server.' => 'Deletes log and session and removes <code>%s</code> from the server.',
		'Abschließen &amp; Skript löschen' => 'Finish &amp; delete script',
	];
}

// ============================================================================
// Ausgabe
// ============================================================================

function wprc_page(string $title, string $body, int $step = 0, bool $show_switch = true): void
{
	$nav = '';
	if ($step > 0) {
		$nav .= '<ol class="steps">';
		foreach (WPRC_STEPS as $n => $label) {
			$cls = $n === $step ? 'cur' : ($n < $step ? 'done' : '');
			$nav .= '<li class="' . $cls . '"><a href="' . h(wprc_url(['step' => $n])) . '"><span>' . $n . '</span>' . h(wprc_t($label)) . '</a></li>';
		}
		$nav .= '</ol>';
	}
	$flash = '';
	foreach ($_SESSION['flash'] ?? [] as [$type, $key, $args]) {
		$flash .= '<div class="note ' . h($type) . '">' . h(wprc_t($key, ...array_values($args))) . '</div>';
	}
	unset($_SESSION['flash']);
	$lang = wprc_lang();
	$langs = [];
	foreach (WPRC_LANGS as $code => $label) {
		$langs[] = $code === $lang
			? '<strong aria-current="true">' . h($label) . '</strong>'
			: '<a href="' . h(wprc_url(($step > 0 ? ['step' => $step] : []) + ['lang' => $code])) . '" hreflang="' . h($code) . '" lang="' . h($code) . '">' . h($label) . '</a>';
	}
	$switch = !$show_switch ? '' : '<nav class="lang" aria-label="' . h(wprc_t('Sprache')) . '">' . implode(' <span aria-hidden="true">|</span> ', $langs) . '</nav>';
	$logout = !empty($_SESSION['auth']) ? '<form method="post" class="inline"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf'] ?? '') . '"><button name="action" value="logout" class="link">' . h(wprc_t('Abmelden')) . '</button></form>' : '';
	echo '<!doctype html><html lang="' . h($lang) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
		. '<meta name="robots" content="noindex, nofollow"><title>' . h($title) . ' · ushort Redirect Cleaner</title><style>' . wprc_css() . '</style></head><body>'
		. '<header><div class="wrap"><div class="brand"><strong>ushort Redirect Cleaner</strong> <small>v' . WPRC_VERSION . '</small></div><div class="tools">' . $switch . $logout . '</div></div></header>'
		. '<main class="wrap">' . $nav . $flash . '<h1>' . h($title) . '</h1>' . $body . '</main>'
		. '<footer><div class="wrap">' . wprc_t('Entwickelt von %s', h(WPRC_AUTHOR)) . ', <a href="' . h(WPRC_BRAND_URL) . '" target="_blank" rel="noopener noreferrer">' . h(WPRC_BRAND) . '</a> · '
		. h(wprc_t('Ohne Gewähr – vorher immer ein vollständiges Backup anlegen.')) . '</div></footer></body></html>';
	exit;
}

function wprc_css(): string
{
	return ':root{--bg:#f6f6f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e2e2dc;--accent:#f2c500;--accent-ink:#1d1d1b;--ok:#1f7a3d;--warn:#9a6700;--err:#b42318;--code:#f1f1ec}'
		. '@media (prefers-color-scheme:dark){:root{--bg:#151513;--card:#1f1f1c;--ink:#ecece6;--muted:#a3a39b;--line:#34342f;--code:#2a2a26;--ok:#5cc27f;--warn:#e0b44a;--err:#ff7b6b}}'
		. '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}'
		. '.wrap{max-width:980px;margin:0 auto;padding:0 16px}header{background:var(--card);border-bottom:3px solid var(--accent)}header .wrap{display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:56px}'
		. '.tools{display:flex;gap:18px;align-items:center}.lang{font-size:.88rem;color:var(--muted)}.lang a{color:var(--muted)}.lang strong{color:var(--ink)}'
		. '.brand small{color:var(--muted)}h1{font-size:1.5rem;margin:1.2rem 0 .8rem}h2{font-size:1.15rem;margin:1.6rem 0 .6rem}h3{font-size:1rem;margin:1.2rem 0 .4rem}'
		. 'main{padding-bottom:3rem}footer{border-top:1px solid var(--line);color:var(--muted);font-size:.85rem;padding:1rem 0 2rem}a{color:inherit}'
		. '.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}.card>h2:first-child,.card>h3:first-child{margin-top:0}'
		. '.steps{display:flex;flex-wrap:wrap;gap:6px;list-style:none;padding:0;margin:18px 0 0}.steps a{display:flex;gap:6px;align-items:center;text-decoration:none;padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:var(--card);font-size:.88rem;color:var(--muted)}'
		. '.steps span{display:inline-grid;place-items:center;width:20px;height:20px;border-radius:50%;background:var(--line);font-size:.75rem;color:var(--ink)}.steps .cur a{border-color:var(--accent);color:var(--ink);font-weight:600}.steps .cur span,.steps .done span{background:var(--accent);color:var(--accent-ink)}'
		. 'table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}'
		. '.tbl{overflow-x:auto}pre,code{font-family:ui-monospace,Consolas,monospace;font-size:.85rem}pre{background:var(--code);padding:10px 12px;border-radius:8px;white-space:pre-wrap;word-break:break-all;margin:8px 0}'
		. '.note{padding:10px 14px;border-radius:8px;margin:10px 0;border-left:4px solid var(--muted);background:var(--card)}.note.ok{border-color:var(--ok)}.note.warn{border-color:var(--warn)}.note.error{border-color:var(--err)}'
		. '.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.8rem;font-weight:600;border:1px solid currentColor}.b-ok{color:var(--ok)}.b-warn{color:var(--warn)}.b-err{color:var(--err)}.b-muted{color:var(--muted)}'
		. 'label{display:block;margin:6px 0}input[type=text],input[type=password],input[type=url]{width:100%;max-width:520px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}'
		. '.btn,button{font:inherit;cursor:pointer;border-radius:6px;padding:9px 16px;border:1px solid var(--line);background:var(--card);color:var(--ink)}.btn.primary,button.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}'
		. 'button.danger{background:var(--err);border-color:var(--err);color:#fff;font-weight:600}button.link{border:0;background:none;text-decoration:underline;padding:0;color:var(--muted)}.inline{display:inline}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;align-items:center}'
		. '.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.stat{font-size:1.6rem;font-weight:700}ul.plain{margin:4px 0;padding-left:18px}';
}

function wprc_badge(bool $good, string $yes, string $no, bool $warn_only = false): string
{
	return $good ? '<span class="badge b-ok">' . h($yes) . '</span>' : '<span class="badge ' . ($warn_only ? 'b-warn' : 'b-err') . '">' . h($no) . '</span>';
}

function wprc_csrf_field(): string
{
	return '<input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">';
}

function wprc_scan_summary(array $scan): string
{
	$out = '<div class="grid">'
		. '<div class="card"><div class="muted">' . h(wprc_t('Infizierte Einträge')) . '</div><div class="stat">' . (int) $scan['infected'] . '</div></div>'
		. '<div class="card"><div class="muted">' . h(wprc_t('Payload-Varianten')) . '</div><div class="stat">' . count($scan['payloads']) . '</div></div>'
		. '<div class="card"><div class="muted">' . h(wprc_t('Schad-Hosts')) . '</div><div class="stat">' . count($scan['hosts']) . '</div></div>'
		. '</div>';
	foreach ($scan['payloads'] as $hash => $pl) {
		$types = [];
		foreach ($pl['types'] as $t => $n) {
			$types[] = h($t) . ': ' . (int) $n;
		}
		$out .= '<div class="card"><h3>Payload ' . h(substr($hash, 0, 10)) . ' <span class="badge b-err">' . h(wprc_t('%d Einträge', $pl['count'])) . '</span></h3>'
			. '<pre>' . h($pl['payload']) . '</pre>'
			. '<div class="muted">' . h(wprc_t('Verteilung')) . ': ' . implode(' · ', $types) . '</div>'
			. ($pl['samples'] ? '<div class="muted">' . h(wprc_t('Beispiele')) . ': ' . h(implode(', ', $pl['samples'])) . '</div>' : '') . '</div>';
	}
	return $out;
}

// ============================================================================
// Ablauf
// ============================================================================

// Zugangsschlüssel prüfen, bevor irgendetwas anderes passiert
if (strlen(WPRC_ACCESS_KEY) < 16) {
	session_start();
	wprc_lang_from_request();
	$_SESSION['csrf'] = $_SESSION['csrf'] ?? '';
	wprc_page(wprc_t('Einrichtung erforderlich'), '<div class="note warn">' . h(wprc_t('Der Wizard ist gesperrt, bis in dieser Datei ein Zugangsschlüssel gesetzt ist.')) . '</div>'
		. '<div class="card"><ol><li>' . wprc_t('Datei <code>%s</code> lokal öffnen.', h(basename(__FILE__))) . '</li>'
		. '<li>' . wprc_t('Bei <code>%s</code> einen zufälligen Schlüssel mit mindestens 16 Zeichen eintragen, z.&nbsp;B. <code>%s</code>', h("const WPRC_ACCESS_KEY = '';"), h(bin2hex(random_bytes(16)))) . '</li>'
		. '<li>' . h(wprc_t('Datei erneut hochladen und diese Seite neu laden.')) . '</li></ol></div>');
}

$client_ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
if (WPRC_ALLOWED_IPS && !in_array($client_ip, WPRC_ALLOWED_IPS, true)) {
	http_response_code(403);
	exit(wprc_t('Zugriff verweigert.'));
}

session_name('wprc_' . substr(sha1(__FILE__), 0, 8));
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => wprc_is_https(), 'httponly' => true, 'samesite' => 'Strict']);
session_start();
wprc_lang_from_request();
if (empty($_SESSION['csrf'])) {
	$_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$key_hash = hash('sha256', WPRC_ACCESS_KEY . __FILE__);
$authed = isset($_SESSION['auth']) && hash_equals($key_hash, (string) $_SESSION['auth']);
$action = (string) ($_POST['action'] ?? ($_GET['action'] ?? ''));

// Login
if (!$authed) {
	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
		if (hash_equals((string) $_SESSION['csrf'], (string) ($_POST['csrf'] ?? '')) && hash_equals(WPRC_ACCESS_KEY, (string) ($_POST['key'] ?? ''))) {
			session_regenerate_id(true);
			$_SESSION['auth'] = $key_hash;
			$_SESSION['log'] = [];
			wprc_log('Anmeldung von %s.', [$client_ip]);
			wprc_redirect(['step' => 1]);
		}
		sleep(2);
		wprc_flash('Zugangsschlüssel falsch.', [], 'error');
	}
	wprc_page(wprc_t('Anmelden'), '<div class="card"><form method="post">' . wprc_csrf_field()
		. '<label>' . wprc_t('Zugangsschlüssel (aus <code>WPRC_ACCESS_KEY</code>)') . '<input type="password" name="key" autocomplete="off" autofocus required></label>'
		. '<div class="actions"><button class="primary" name="action" value="login">' . h(wprc_t('Anmelden')) . '</button></div></form></div>'
		. '<p class="muted">' . wprc_t('Dieses Werkzeug liest die Zugangsdaten aus der <code>wp-config.php</code> und kann die Datenbank verändern. Nach Abschluss löscht es sich selbst.') . '</p>');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !hash_equals((string) $_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
	http_response_code(400);
	wprc_page(wprc_t('Ungültige Anfrage'), '<div class="note error">' . h(wprc_t('Sicherheitstoken ungültig. Bitte Seite neu laden.')) . '</div>');
}

if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$lang = $_SESSION['lang'] ?? null;
	$_SESSION = [];
	session_destroy();
	wprc_redirect($lang ? ['lang' => $lang] : []);
}

if ($action === 'log') {
	header('Content-Type: text/plain; charset=utf-8');
	header('Content-Disposition: attachment; filename="wordpress-ushort-redirect-cleaner-' . date('Ymd-His') . '.log"');
	echo 'ushort Redirect Cleaner ' . WPRC_VERSION . ' – ' . wprc_t('Protokoll') . "\n" . str_repeat('=', 60) . "\n";
	foreach (wprc_log_lines() as $line) {
		echo $line . "\n";
	}
	exit;
}

// Manuelle DB-Zugangsdaten (Fallback, wenn wp-config.php nicht statisch lesbar ist)
if ($action === 'manual_db' && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$prefix = (string) ($_POST['prefix'] ?? 'wp_');
	if (!preg_match('~^[A-Za-z0-9_]+$~', $prefix)) {
		wprc_flash('Ungültiges Tabellenpräfix.', [], 'error');
	} else {
		$_SESSION['manual_db'] = ['name' => (string) $_POST['name'], 'user' => (string) $_POST['user'], 'pass' => (string) $_POST['pass'], 'host' => (string) ($_POST['host'] ?: 'localhost'), 'prefix' => $prefix];
		wprc_log('Manuelle DB-Zugangsdaten gesetzt (Host %s, DB %s).', [$_SESSION['manual_db']['host'], $_SESSION['manual_db']['name']]);
	}
	wprc_redirect(['step' => 1]);
}

$cfg = wprc_db_settings();
$db = null;
$db_error = null;
if (!$cfg['missing']) {
	if (!preg_match('~^[A-Za-z0-9_]+$~', (string) $cfg['prefix'])) {
		$db_error = wprc_t('Tabellenpräfix enthält unzulässige Zeichen.');
	} else {
		try {
			$db = wprc_connect($cfg);
			if (!wprc_table_exists($db, $cfg['prefix'] . 'posts')) {
				$db_error = wprc_t('Tabelle %s nicht gefunden – stimmt das Präfix?', $cfg['prefix'] . 'posts');
				$db = null;
			}
		} catch (Throwable $e) {
			$db_error = wprc_t('Verbindung fehlgeschlagen: %s', $e->getMessage());
		}
	}
}

if (!$db) {
	$msg = $cfg['missing'] ? wprc_t('Aus der wp-config.php konnten nicht alle Werte statisch gelesen werden: %s.', implode(', ', $cfg['missing'])) : (string) $db_error;
	$c = $cfg['consts'];
	wprc_page(wprc_t('Datenbankverbindung'), '<div class="note error">' . h($msg) . '</div>'
		. '<div class="card"><p>' . h(wprc_t('Zugangsdaten bitte manuell eintragen (sie werden nur in der Session gehalten):')) . '</p><form method="post">' . wprc_csrf_field()
		. '<label>' . h(wprc_t('Datenbankname')) . '<input type="text" name="name" value="' . h($c['DB_NAME'] ?? '') . '" required></label>'
		. '<label>' . h(wprc_t('Benutzer')) . '<input type="text" name="user" value="' . h($c['DB_USER'] ?? '') . '" required></label>'
		. '<label>' . h(wprc_t('Passwort')) . '<input type="password" name="pass" autocomplete="off"></label>'
		. '<label>Host<input type="text" name="host" value="' . h($c['DB_HOST'] ?? 'localhost') . '"></label>'
		. '<label>' . h(wprc_t('Tabellenpräfix')) . '<input type="text" name="prefix" value="' . h($cfg['prefix'] ?? 'wp_') . '" required></label>'
		. '<div class="actions"><button class="primary" name="action" value="manual_db">' . h(wprc_t('Verbinden')) . '</button></div></form></div>');
}

$p = $cfg['prefix'];
$consts = $cfg['consts'];
$trusted = wprc_trusted_hosts($consts);
$extra_hosts = $_SESSION['extra_hosts'] ?? [];

// ---------------------------------------------------------------------------
// Aktionen
// ---------------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if ($action === 'extra_hosts') {
		$list = preg_split('~[\s,;]+~', (string) ($_POST['hosts'] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
		$_SESSION['extra_hosts'] = array_values(array_unique(array_filter(array_map(function ($h) {
			$h = wprc_host_of(strpos($h, '//') === false ? '//' . $h : $h);
			return preg_match('~^[a-z0-9.\-]+\.[a-z]{2,}$~', $h) ? $h : '';
		}, $list))));
		wprc_log('Zusätzliche Such-Hosts: %s', [implode(', ', $_SESSION['extra_hosts']) ?: '–']);
		wprc_redirect(['step' => 2]);
	}

	if ($action === 'resolve') {
		$scan = wprc_scan($db, $p, $trusted, $extra_hosts);
		$url = (string) ($_POST['url'] ?? '');
		if (in_array($url, $scan['urls'], true)) {
			$_SESSION['chains'][$url] = wprc_resolve_chain($url);
			wprc_log('Weiterleitungskette abgerufen für %s: %d Station(en).', [$url, count($_SESSION['chains'][$url])]);
		}
		wprc_redirect(['step' => 2]);
	}

	if ($action === 'set_home') {
		$scan = wprc_scan($db, $p, $trusted, $extra_hosts);
		$choice = (string) ($_POST['home_choice'] ?? '');
		$url = $choice === 'manual' ? (string) ($_POST['home_manual'] ?? '') : $choice;
		$valid = wprc_validate_home($url, $scan['hosts']);
		if (!$valid) {
			wprc_flash('Ungültige Home-URL. Erlaubt ist http(s)://host[/pfad] ohne Query; Schad-Hosts sind ausgeschlossen.', [], 'error');
			wprc_redirect(['step' => 3]);
		}
		$_SESSION['home_url'] = $valid;
		wprc_log('Home-URL festgelegt: %s', [$valid]);
		wprc_redirect(['step' => 4]);
	}

	if ($action === 'save_options') {
		$_SESSION['opt'] = [
			'payloads' => array_values(array_map('strval', (array) ($_POST['payloads'] ?? []))),
			'core' => !empty($_POST['core']),
			'yoast' => !empty($_POST['yoast']),
			'revisions' => !empty($_POST['revisions']),
			'backup' => !empty($_POST['backup']),
		];
		wprc_log('Optionen gespeichert: %s', [json_encode($_SESSION['opt'])]);
		wprc_redirect(['step' => 5]);
	}

	if ($action === 'run') {
		if (empty($_POST['confirm'])) {
			wprc_flash('Bitte bestätigen, dass ein aktuelles Datenbank-Backup vorliegt.', [], 'error');
			wprc_redirect(['step' => 5]);
		}
		if (empty($_SESSION['home_url']) || empty($_SESSION['opt'])) {
			wprc_flash('Home-URL und Optionen fehlen.', [], 'error');
			wprc_redirect(['step' => 3]);
		}
		$scan = wprc_scan($db, $p, $trusted, $extra_hosts);
		try {
			$_SESSION['result'] = wprc_run($db, $p, $scan, $_SESSION['opt'], $_SESSION['home_url']);
			wprc_flash('Bereinigung erfolgreich abgeschlossen.', [], 'ok');
		} catch (Throwable $e) {
			wprc_flash('Fehler: %s – es wurde nichts geändert.', [$e->getMessage()], 'error');
			wprc_redirect(['step' => 5]);
		}
		wprc_redirect(['step' => 6]);
	}

	if ($action === 'finish') {
		$lang = wprc_lang();
		$notes = [];
		if (!empty($_POST['drop_backup']) && wprc_table_exists($db, $p . 'wprc_backup')) {
			$db->query("DROP TABLE `{$p}wprc_backup`");
			$notes[] = ['ok', wprc_t('Backup-Tabelle %s gelöscht.', $p . 'wprc_backup')];
		}
		$_SESSION = [];
		session_destroy();
		setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => '/', 'secure' => wprc_is_https(), 'httponly' => true, 'samesite' => 'Strict']);
		// Sprache für die letzte Seite beibehalten, ohne die Session wieder anzulegen
		$_SESSION['lang'] = $lang;
		$notes[] = ['ok', wprc_t('Session und Protokoll gelöscht.')];
		$deleted = @unlink(__FILE__);
		$notes[] = $deleted ? ['ok', wprc_t('Skriptdatei %s gelöscht.', basename(__FILE__))] : ['error', wprc_t('Skriptdatei konnte NICHT gelöscht werden – bitte sofort per FTP/SSH entfernen!')];
		$body = '';
		foreach ($notes as [$type, $n]) {
			$body .= '<div class="note ' . $type . '">' . h($n) . '</div>';
		}
		wprc_page(wprc_t('Fertig'), $body . '<div class="card"><h2>' . h(wprc_t('Nächste Schritte')) . '</h2><ul class="plain">'
			. '<li>' . wprc_t('Elementor: <em>Werkzeuge → Dateien &amp; Daten regenerieren</em>, Seiten-/Server-Cache leeren.') . '</li>'
			. '<li>' . wprc_t('Zugangsdaten ändern: Datenbank, FTP/SFTP/SSH, Hosting-Konto, alle WordPress-Admins; neue Salts in der <code>wp-config.php</code>.') . '</li>'
			. '<li>' . h(wprc_t('Einfallstor klären (Server-/FTP-Logs, weitere Installationen im selben Hosting-Konto).')) . '</li>'
			. '<li>' . h(wprc_t('Seite mobil prüfen (Smartphone bzw. Mobile-Emulation), Google Search Console auf Sicherheitsprobleme prüfen.')) . '</li></ul></div>', 0, false);
	}
}

// ---------------------------------------------------------------------------
// Schritte
// ---------------------------------------------------------------------------

$step = max(1, min(6, (int) ($_GET['step'] ?? 1)));
$scan = wprc_scan($db, $p, $trusted, $extra_hosts);
$f = wprc_csrf_field();

if ($step === 1) {
	$hl = wprc_health($db, $p, $consts);
	$y = $scan['yoast'];
	$body = '<p class="muted">' . h(wprc_t('Nur lesend – in diesem Schritt wird nichts verändert.')) . '</p>' . wprc_scan_summary($scan);
	if (!$scan['infected']) {
		$body .= '<div class="note ok">' . h(wprc_t('Keine Redirect-Injektion am Anfang von Beitragsinhalten gefunden.')) . '</div>';
	}

	$body .= '<h2>' . h(wprc_t('Website-URLs')) . '</h2><div class="card tbl"><table><tr><th>' . h(wprc_t('Quelle')) . '</th><th>' . h(wprc_t('Wert')) . '</th><th>Status</th></tr>';
	foreach ($scan['core'] as $name => $c) {
		$body .= '<tr><td>Option <code>' . h($name) . '</code></td><td><code>' . h($c['value']) . '</code></td><td>'
			. ($c['malicious'] ? '<span class="badge b-err">' . h(wprc_t('Schad-Host')) . '</span>' : ($c['untrusted'] ? '<span class="badge b-warn">' . h(wprc_t('weicht vom aktuellen Host ab')) . '</span>' : '<span class="badge b-ok">ok</span>')) . '</td></tr>';
	}
	foreach (['WP_HOME', 'WP_SITEURL'] as $k) {
		if (isset($consts[$k])) {
			$body .= '<tr><td><code>' . $k . '</code> (wp-config.php)</td><td><code>' . h($consts[$k]) . '</code></td><td></td></tr>';
		}
	}
	$body .= '</table></div>';

	$body .= '<h2>Yoast SEO</h2><div class="card">'
		. h(wprc_t('Plugin aktiv')) . ': ' . wprc_badge($y['active'], wprc_t('ja'), wprc_t('nein'), true)
		. ' &nbsp; Option <code>wpseo</code>: ' . wprc_badge($y['option'], wprc_t('vorhanden'), wprc_t('fehlt'), true)
		. ' &nbsp; ' . h(wprc_t('Tabelle')) . ' <code>' . h($p) . 'yoast_indexable</code>: ' . wprc_badge($y['table'], wprc_t('vorhanden'), wprc_t('fehlt'), true);
	if ($y['home_url'] !== null) {
		$body .= '<p>' . wprc_t('Gecachte <code>home_url</code>') . ': <code>' . h($y['home_url']) . '</code> ' . ($y['home_url_malicious'] ? '<span class="badge b-err">' . h(wprc_t('Schad-Host')) . '</span>' : '<span class="badge b-ok">ok</span>') . '</p>';
	}
	$body .= $y['table'] ? '<p>' . h(wprc_t('Indexables mit Schad-Host')) . ': <strong>' . (int) $y['indexables'] . '</strong></p>' : '';
	$body .= '</div>';

	$body .= '<h2>' . h(wprc_t('Weitere Prüfpunkte')) . '</h2><div class="card tbl"><table>'
		. '<tr><th>PHP / MySQL</th><td>' . h(PHP_VERSION) . ' / ' . h($hl['mysql']) . '</td></tr>'
		. '<tr><th>WordPress</th><td>' . h($hl['wp'] ?? wprc_t('unbekannt')) . '</td></tr>'
		. '<tr><th>' . h(wprc_t('Konfiguration')) . '</th><td>' . wprc_t('%s, Präfix <code>%s</code>, DB <code>%s</code>', h(wprc_t((string) $cfg['source'])), h($p), h($consts['DB_NAME'] ?? '')) . '</td></tr>';
	$engine_bad = array_filter($hl['engines'], function ($e) {
		return strtolower((string) $e) !== 'innodb';
	});
	$body .= '<tr><th>' . h(wprc_t('Tabellen-Engine')) . '</th><td>' . ($engine_bad
		? '<span class="badge b-warn">' . h(wprc_t('nicht InnoDB: %s', implode(', ', array_keys($engine_bad)))) . '</span>' . h(wprc_t(' – keine Rollback-Sicherheit, Backup ist Pflicht'))
		: '<span class="badge b-ok">InnoDB</span>') . '</td></tr>';
	if ($hl['updraft']) {
		$v = $hl['updraft'];
		$udc = '';
		if (version_compare($v, '1.26.4', '<=')) {
			$udc .= ' <span class="badge b-err">' . h(wprc_t('anfällig für CVE-2026-10795')) . '</span>';
		}
		if (version_compare($v, '1.26.13', '<')) {
			$udc .= ' <span class="badge b-err">' . h(wprc_t('vor 1.26.13 (UpdraftCentral-Schlüsselvorfall 10/2026)')) . '</span>';
		}
		$body .= '<tr><th>UpdraftPlus</th><td>' . h($v) . ($udc ?: ' <span class="badge b-ok">' . h(wprc_t('aktuell genug')) . '</span>')
			. '<br>' . h(wprc_t('UpdraftCentral-Schlüssel')) . ': ' . wprc_badge(!$hl['udc_keys'], wprc_t('keine'), wprc_t('vorhanden – prüfen/löschen'))
			. ' · Client-Log: ' . wprc_badge(!$hl['udc_log'], wprc_t('keins'), wprc_t('vorhanden – auf „Command received“ prüfen'), true) . '</td></tr>';
	}
	$body .= '<tr><th>' . h(wprc_t('Must-Use-Plugins')) . '</th><td>' . ($hl['mu'] ? '<span class="badge b-warn">' . h(implode(', ', $hl['mu'])) . '</span>' : '<span class="badge b-ok">' . h(wprc_t('keine')) . '</span>') . '</td></tr>'
		. '<tr><th>Drop-ins</th><td>' . ($hl['dropins'] ? h(implode(', ', $hl['dropins'])) : '<span class="badge b-ok">' . h(wprc_t('keine')) . '</span>') . '</td></tr>'
		. '<tr><th>' . h(wprc_t('Neue Benutzer (30 Tage)')) . '</th><td>' . (int) $hl['new_users'] . '</td></tr>'
		. '<tr><th>' . h(wprc_t('Administratoren')) . '</th><td><ul class="plain">';
	foreach ($hl['admins'] as $a) {
		$body .= '<li><code>' . h($a['user_login']) . '</code> · ' . h($a['user_email'] ?: '–') . ' · ' . h(wprc_t('seit %s', $a['user_registered'])) . '</li>';
	}
	$body .= '</ul></td></tr></table></div>'
		. '<div class="actions"><a class="btn primary" href="' . h(wprc_url(['step' => 2])) . '">' . h(wprc_t('Weiter: Recherche')) . '</a></div>';
	wprc_page('1 · ' . wprc_t('Sichtung'), $body, 1);
}

if ($step === 2) {
	$body = '<p class="muted">' . h(wprc_t('Gefundene Schad-URLs mit externen Prüfdiensten abgleichen. Die Links öffnen sich ohne Referrer.')) . '</p>';
	if (!$scan['urls']) {
		$body .= '<div class="note ok">' . h(wprc_t('Keine Schad-URLs in Payloads gefunden.')) . '</div>';
	}
	foreach ($scan['urls'] as $url) {
		$host = wprc_host_of($url);
		$ips = wprc_dns($host);
		$links = [];
		foreach (wprc_lookup_links($url) as $label => $l) {
			$links[] = '<a href="' . h($l) . '" target="_blank" rel="noopener noreferrer">' . h($label) . '</a>';
		}
		$body .= '<div class="card"><h3><code>' . h($url) . '</code></h3>'
			. '<p>Host: <code>' . h($host) . '</code> · DNS: ' . ($ips ? '<code>' . h(implode(', ', $ips)) . '</code>' : '<span class="muted">' . h(wprc_t('keine Auflösung')) . '</span>') . '</p>'
			. '<p>' . implode(' · ', $links) . '</p>';
		$occ = $scan['occurrences'][$host] ?? null;
		if ($occ) {
			$body .= '<p class="muted">' . h(wprc_t('Vorkommen in der DB: Beiträge %d · Postmeta %d · Kommentare %d · Benutzer %d', $occ['posts_total'], $occ['postmeta'], $occ['comments'], $occ['users']))
				. (isset($occ['yoast_indexable']) ? h(wprc_t(' · Yoast-Indexables %d', $occ['yoast_indexable'])) : '')
				. ($occ['options'] ? '<br>' . h(wprc_t('Optionen')) . ': <code>' . h(implode(', ', $occ['options'])) . '</code>' : '') . '</p>';
			$rest = $occ['posts_total'] - $scan['infected'];
			if ($rest > 0 || $occ['postmeta'] || $occ['comments'] || $occ['users']) {
				$body .= '<div class="note warn">' . wprc_t('Es gibt Vorkommen außerhalb des erkannten Payloads (z.&nbsp;B. Postmeta). Diese werden nicht automatisch bereinigt – bitte manuell prüfen.') . '</div>';
			}
		}
		$chain = $_SESSION['chains'][$url] ?? null;
		if ($chain) {
			$body .= '<div class="tbl"><table><tr><th>#</th><th>URL</th><th>Status</th><th>' . h(wprc_t('Weiter nach')) . '</th><th>Server/IP</th></tr>';
			foreach ($chain as $i => $hop) {
				$body .= '<tr><td>' . ($i + 1) . '</td><td><code>' . h($hop['url']) . '</code></td><td>' . h($hop['error'] ?? (string) $hop['status']) . '</td><td><code>' . h($hop['location'] ?? '') . '</code></td><td>' . h(trim(($hop['server'] ?? '') . ' ' . ($hop['ip'] ?? ''))) . '</td></tr>';
			}
			$body .= '</table></div>';
		}
		$body .= '<form method="post">' . $f . '<input type="hidden" name="url" value="' . h($url) . '"><div class="actions"><button name="action" value="resolve">' . h(wprc_t('Weiterleitungskette abrufen')) . '</button>'
			. '<span class="muted">' . h(wprc_t('HEAD-Request vom Server aus, ohne Inhalte zu laden. Der Betreiber der Domain sieht dabei die Server-IP.')) . '</span></div></form></div>';
	}
	$body .= '<h2>' . h(wprc_t('Zusätzliche Domains durchsuchen')) . '</h2><div class="card"><form method="post">' . $f
		. '<label>' . wprc_t('Weitere verdächtige Hosts (kommagetrennt), z.&nbsp;B. bekannte Varianten derselben Kampagne') . '<input type="text" name="hosts" value="' . h(implode(', ', $extra_hosts)) . '" placeholder="ushort.today, u-short.net"></label>'
		. '<div class="actions"><button name="action" value="extra_hosts">' . h(wprc_t('Suchen')) . '</button></div></form>';
	foreach ($extra_hosts as $eh) {
		$o = $scan['occurrences'][$eh] ?? null;
		if ($o) {
			$body .= '<p>' . wprc_t('<code>%s</code>: Beiträge %d · Postmeta %d · Optionen %d', h($eh), $o['posts_total'], $o['postmeta'], count($o['options'])) . '</p>';
		}
	}
	$body .= '</div><div class="actions"><a class="btn" href="' . h(wprc_url(['step' => 1])) . '">' . h(wprc_t('Zurück')) . '</a><a class="btn primary" href="' . h(wprc_url(['step' => 3])) . '">' . h(wprc_t('Weiter: Home-URL')) . '</a></div>';
	wprc_page('2 · ' . wprc_t('Recherche'), $body, 2);
}

if ($step === 3) {
	$cands = wprc_home_candidates($consts, $scan);
	$current = $_SESSION['home_url'] ?? (reset($cands) ?: '');
	$body = '<p class="muted">' . wprc_t('Diese URL ersetzt die Schad-URL in Yoast und (falls betroffen) in <code>home</code>/<code>siteurl</code>. Ohne abschließenden Schrägstrich.') . '</p><div class="card"><form method="post">' . $f;
	$manual = true;
	foreach ($cands as $label => $url) {
		$sel = $url === $current;
		$manual = $manual && !$sel;
		$body .= '<label><input type="radio" name="home_choice" value="' . h($url) . '"' . ($sel ? ' checked' : '') . '> <code>' . h($url) . '</code> <span class="muted">– ' . h($label) . '</span></label>';
	}
	$body .= '<label><input type="radio" name="home_choice" value="manual"' . ($manual ? ' checked' : '') . '> ' . h(wprc_t('Manuell eintragen:')) . '</label>'
		. '<input type="url" name="home_manual" value="' . h($manual ? $current : '') . '" placeholder="' . h(wprc_t('https://www.example.de')) . '">'
		. '<div class="actions"><a class="btn" href="' . h(wprc_url(['step' => 2])) . '">' . h(wprc_t('Zurück')) . '</a><button class="primary" name="action" value="set_home">' . wprc_t('Übernehmen &amp; weiter') . '</button></div></form></div>';
	wprc_page('3 · ' . wprc_t('Home-URL'), $body, 3);
}

if (empty($_SESSION['home_url']) && $step >= 4) {
	wprc_flash('Bitte zuerst die Home-URL festlegen.', [], 'warn');
	wprc_redirect(['step' => 3]);
}

if ($step === 4) {
	$opt = $_SESSION['opt'] ?? ['payloads' => array_keys($scan['payloads']), 'core' => true, 'yoast' => true, 'revisions' => false, 'backup' => true];
	$y = $scan['yoast'];
	$body = '<form method="post">' . $f . '<div class="card"><h2>' . h(wprc_t('Beitragsinhalte')) . '</h2>';
	if (!$scan['payloads']) {
		$body .= '<p class="muted">' . h(wprc_t('Keine Payloads gefunden.')) . '</p>';
	}
	foreach ($scan['payloads'] as $hash => $pl) {
		$body .= '<label><input type="checkbox" name="payloads[]" value="' . h($hash) . '"' . (in_array($hash, $opt['payloads'], true) ? ' checked' : '') . '> '
			. wprc_t('Payload <code>%s</code> aus <strong>%d</strong> Einträgen entfernen', h(substr($hash, 0, 10)), $pl['count']) . '</label>';
	}
	$body .= '</div>';
	$core_bad = array_filter($scan['core'], function ($c) {
		return $c['malicious'];
	});
	$body .= '<div class="card"><h2>' . h(wprc_t('Website-URLs')) . '</h2>' . ($core_bad
		? '<label><input type="checkbox" name="core" value="1"' . ($opt['core'] ? ' checked' : '') . '> ' . wprc_t('<code>%s</code> auf <code>%s</code> setzen', h(implode(', ', array_keys($core_bad))), h($_SESSION['home_url'])) . '</label>'
			. '<p class="muted">' . wprc_t('Liegt WordPress in einem Unterverzeichnis, <code>siteurl</code> danach manuell prüfen.') . '</p>'
		: '<p class="muted">' . wprc_t('<code>home</code> und <code>siteurl</code> sind nicht betroffen.') . '</p>') . '</div>';
	$body .= '<div class="card"><h2>Yoast SEO</h2>' . ($y['present']
		? '<label><input type="checkbox" name="yoast" value="1"' . ($opt['yoast'] ? ' checked' : '') . '> ' . wprc_t('Yoast bereinigen: gecachte <code>home_url</code>')
			. ($y['home_url_malicious'] ? ' <span class="badge b-err">' . h(wprc_t('betroffen')) . '</span>' : ' <span class="badge b-ok">ok</span>')
			. wprc_t(' und %d Indexables (inkl. <code>permalink_hash</code>)', $y['indexables']) . '</label>'
		: '<p class="muted">' . h(wprc_t('Yoast SEO ist nicht installiert – Schritt entfällt.')) . '</p>') . '</div>';
	$body .= '<div class="card"><h2>' . h(wprc_t('Weitere Optionen')) . '</h2>'
		. '<label><input type="checkbox" name="backup" value="1"' . ($opt['backup'] ? ' checked' : '') . '> ' . wprc_t('Originalwerte in Tabelle <code>%s</code> sichern (empfohlen)', h($p . 'wprc_backup')) . '</label>'
		. '<label><input type="checkbox" name="revisions" value="1"' . ($opt['revisions'] ? ' checked' : '') . '> ' . h(wprc_t('Alle Revisionen löschen (nach der Bereinigung; nicht im Backup enthalten)')) . '</label></div>'
		. '<div class="actions"><a class="btn" href="' . h(wprc_url(['step' => 3])) . '">' . h(wprc_t('Zurück')) . '</a><button class="primary" name="action" value="save_options">' . wprc_t('Speichern &amp; weiter') . '</button></div></form>';
	wprc_page('4 · ' . wprc_t('Optionen'), $body, 4);
}

if ($step === 5) {
	$opt = $_SESSION['opt'] ?? null;
	if (!$opt) {
		wprc_redirect(['step' => 4]);
	}
	$n = 0;
	foreach ($opt['payloads'] as $hash) {
		$n += $scan['payloads'][$hash]['count'] ?? 0;
	}
	$list = '<li>' . wprc_t('Beitragsinhalte: <strong>%d</strong> Einträge', $n) . '</li>';
	if ($opt['core']) {
		foreach ($scan['core'] as $name => $c) {
			if ($c['malicious']) {
				$list .= '<li>Option <code>' . h($name) . '</code> → <code>' . h($_SESSION['home_url']) . '</code></li>';
			}
		}
	}
	if ($opt['yoast'] && $scan['yoast']['present']) {
		$list .= '<li>' . wprc_t('Yoast: <code>home_url</code> %s, %d Indexables', h(wprc_t($scan['yoast']['home_url_malicious'] ? 'ersetzen' : 'unverändert')), $scan['yoast']['indexables']) . '</li>';
	}
	if ($opt['revisions']) {
		$list .= '<li>' . wprc_t('Revisionen löschen: <strong>%d</strong>', (int) wprc_val($db, "SELECT COUNT(*) FROM `{$p}posts` WHERE post_type = 'revision'")) . '</li>';
	}
	$list .= '<li>' . wprc_t('Backup-Tabelle: %s', $opt['backup'] ? h(wprc_t('ja')) : '<strong>' . h(wprc_t('nein')) . '</strong>') . '</li>';
	$body = '<div class="card"><h2>' . h(wprc_t('Geplante Änderungen')) . '</h2><ul class="plain">' . $list . '</ul><p class="muted">' . wprc_t('Ersatz-URL: <code>%s</code>', h($_SESSION['home_url'])) . '</p></div>'
		. '<div class="card"><form method="post">' . $f . '<label><input type="checkbox" name="confirm" value="1" required> ' . h(wprc_t('Ich habe ein aktuelles, vollständiges Datenbank-Backup.')) . '</label>'
		. '<div class="actions"><a class="btn" href="' . h(wprc_url(['step' => 4])) . '">' . h(wprc_t('Zurück')) . '</a><button class="danger" name="action" value="run">' . h(wprc_t('Bereinigung jetzt ausführen')) . '</button></div></form></div>';
	wprc_page('5 · ' . wprc_t('Ausführen'), $body, 5);
}

// Schritt 6
$res = $_SESSION['result'] ?? null;
$body = '';
if ($res) {
	$body .= '<div class="grid"><div class="card"><div class="muted">' . h(wprc_t('Beiträge bereinigt')) . '</div><div class="stat">' . (int) $res['posts'] . '</div></div>'
		. '<div class="card"><div class="muted">home/siteurl</div><div class="stat">' . (int) $res['core'] . '</div></div>'
		. '<div class="card"><div class="muted">' . h(wprc_t('Yoast (Option / Indexables)')) . '</div><div class="stat">' . (int) $res['wpseo'] . ' / ' . (int) $res['indexables'] . '</div></div>'
		. '<div class="card"><div class="muted">' . h(wprc_t('Revisionen gelöscht')) . '</div><div class="stat">' . (int) $res['revisions'] . '</div></div></div>';
} else {
	$body .= '<div class="note warn">' . h(wprc_t('In dieser Session wurde noch keine Bereinigung ausgeführt.')) . '</div>';
}
$remaining = 0;
foreach ($scan['occurrences'] as $o) {
	$remaining += $o['posts_total'] + $o['postmeta'] + count($o['options']) + ($o['yoast_indexable'] ?? 0);
}
$body .= '<h2>' . h(wprc_t('Nachkontrolle')) . '</h2>';
if ($scan['infected'] === 0 && $remaining === 0) {
	$body .= '<div class="note ok">' . h(wprc_t('Erneuter Scan: keine Payloads und keine Vorkommen bekannter Schad-Hosts mehr.')) . '</div>';
} else {
	$body .= '<div class="note warn">' . h(wprc_t('Erneuter Scan: %d Payload-Einträge, %d weitere Vorkommen bekannter Schad-Hosts.', $scan['infected'], $remaining)) . '</div>';
}
$body .= '<div class="card"><h2>' . h(wprc_t('Protokoll')) . '</h2><pre>';
foreach (wprc_log_lines() as $line) {
	$body .= h($line) . "\n";
}
$body .= '</pre><a class="btn" href="' . h(wprc_url(['action' => 'log'])) . '">' . h(wprc_t('Protokoll herunterladen')) . '</a></div>';
$has_backup = wprc_table_exists($db, $p . 'wprc_backup');
$body .= '<div class="card"><h2>' . h(wprc_t('Abschließen')) . '</h2><form method="post">' . $f
	. ($has_backup ? '<label><input type="checkbox" name="drop_backup" value="1"> ' . wprc_t('Backup-Tabelle <code>%s</code> löschen (erst, wenn die Website geprüft ist)', h($p . 'wprc_backup')) . '</label>'
		. '<p class="muted">' . wprc_t('Bleibt sie bestehen, später entfernen mit: <code>%s</code>', h('DROP TABLE `' . $p . 'wprc_backup`;')) . '</p>' : '')
	. '<p>' . wprc_t('Löscht Protokoll und Session und entfernt <code>%s</code> vom Server.', h(basename(__FILE__))) . '</p>'
	. '<div class="actions"><button class="danger" name="action" value="finish">' . wprc_t('Abschließen &amp; Skript löschen') . '</button></div></form></div>';
wprc_page('6 · ' . wprc_t('Abschluss'), $body, 6);
