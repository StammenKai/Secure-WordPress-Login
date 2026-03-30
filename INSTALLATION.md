# SM Login Protection & Security Headers – Installationsanleitung

## Übersicht

Ausfuehrliche Benutzerdokumentation:
- `docs/USER-DOKUMENTATION.md`

Zwei Mu-Plugins für WordPress-Sicherheit:

| Datei | Funktion |
|---|---|
| `sm-login-protection.php` | Rate Limiting (Brute-Force) + Custom Login URL |
| `sm-security-headers.php` | Alle empfohlenen HTTP Security Headers |

---

## 1. Installation

### Per FTP/SFTP:
```
wp-content/mu-plugins/sm-login-protection.php
wp-content/mu-plugins/sm-security-headers.php
```

### Per WP-CLI:
```bash
wp eval 'echo WPMU_PLUGIN_DIR;'
# Dateien dorthin kopieren
```

### Per MainWP:
**MainWP → Code Snippets → Add Snippet** → Inhalt jeder Datei einfügen.
Ziel: Alle Child-Sites oder selektiv.

> **Wichtig:** Nach Installation von `sm-login-protection.php` einmal die Permalinks
> unter Einstellungen → Permalinks speichern (Flush Rewrite Rules).

---

## 2. Konfiguration (wp-config.php)

Alle Werte sind optional – die Defaults sind bereits sinnvoll gesetzt.

### Login-Schutz
```php
// Login-Versuche und Sperrdauer anpassen
define( 'SM_LOGIN_MAX_ATTEMPTS', 5 );        // Standard: 5
define( 'SM_LOGIN_LOCKOUT_DURATION', 900 );  // Standard: 900 (15 Min)

// Custom Login-Slug ändern oder deaktivieren
define( 'SM_LOGIN_SLUG', 'mein-login' );     // Standard: 'mein-login'
// define( 'SM_LOGIN_SLUG', '' );            // Leer = deaktiviert
```

### Security Headers
```php
// CSP enforcing einschalten (erst nach Report-Only-Test!)
define( 'SM_CSP_REPORT_ONLY', false );       // Standard: true

// HSTS anpassen
define( 'SM_HSTS_MAX_AGE', 31536000 );       // Standard: 1 Jahr

// Permissions-Policy erweitern
define( 'SM_PERMISSIONS_POLICY', 'camera=(), microphone=(), geolocation=()' );
```

---

## 3. Wichtige Hinweise

### DSGVO-Konformität
- **IP-Adressen** werden nie als Klartext gespeichert – nur als gesalzener SHA-256-Hash
- **CSP-Reports** loggen keine IP-Adressen, nur die blockierte Ressource
- **Referrer-Policy** minimiert übergebene Daten bei Cross-Origin-Requests
- **Transients** laufen automatisch ab (kein manuelles Löschen nötig)

### CSP Report-Only → Enforce
1. Plugin installieren und einige Tage laufen lassen
2. Error-Log prüfen: `[SM Security] CSP Violation: ...`
3. Ggf. CSP-Direktiven per Filter anpassen
4. Dann in `wp-config.php`: `define( 'SM_CSP_REPORT_ONLY', false );`

### CSP pro Plugin erweitern
Wenn ein Plugin externe Ressourcen braucht (z. B. Google reCAPTCHA):

```php
// In functions.php oder eigenem Mu-Plugin:
add_filter( 'sm_csp_directives', function( $directives ) {
    // Google reCAPTCHA erlauben
    $directives[] = "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com";
    $directives[] = "frame-src 'self' https://www.google.com";
    return $directives;
} );
```

### Custom Login URL – Merken!
Die Standard-URL ist jetzt: **example.de/mein-login**

`/wp-login.php` gibt einen 404-Fehler zurück.
Folgende Aktionen funktionieren weiterhin:
- Logout (`?action=logout`)
- Passwort-Reset (`?action=lostpassword`)
- E-Mail-Bestätigungen

---

## 4. Testen

### Rate Limiting testen:
1. Gehe auf `/mein-login`
2. Gib 5x falsche Zugangsdaten ein
3. Beim 6. Versuch → Sperrmeldung (15 Min)

### Security Headers prüfen:
- https://securityheaders.com → URL eingeben
- Browser DevTools → Network-Tab → Response Headers prüfen
- Ziel: **A+ Rating** (nach CSP Enforce)

### Custom Login URL testen:
- `/wp-login.php` → 404
- `/mein-login` → Login-Formular
- `/wp-admin/` (nicht eingeloggt) → Redirect auf `/mein-login`

---

## 5. Deinstallation

Datei(en) einfach aus `mu-plugins/` löschen.
Keine Datenbank-Änderungen nötig (Transients laufen automatisch ab).
Optional: Permalinks einmal neu speichern.

---

## 6. Alternative: Normales Plugin (mit Install/Uninstall)

Zusätzlich zur Mu-Plugin-Variante gibt es jetzt ein reguläres, installierbares Plugin unter:

`sm-security-suite/`

### Struktur
- `sm-security-suite/sm-security-suite.php` (Hauptdatei)
- `sm-security-suite/includes/login-protection.php`
- `sm-security-suite/includes/security-headers.php`
- `sm-security-suite/uninstall.php`

### Installation als normales Plugin
1. Ordner `sm-security-suite` nach `wp-content/plugins/` kopieren.
2. In WordPress unter Plugins aktivieren.
3. Aktivierung führt automatisch `flush_rewrite_rules()` aus.
4. Login- und Header-Werte unter **Einstellungen -> SM Security Suite** im Backend pflegen.

> Hinweis: Konstanten in `wp-config.php` funktionieren weiterhin und haben Vorrang vor den gespeicherten Backend-Einstellungen.

### Deaktivierung
- Beim Deaktivieren werden Rewrite Rules erneut geflusht.

### Deinstallation
- Bei „Plugin löschen" wird `uninstall.php` ausgeführt.
- Entfernt:
    - Option `sm_security_suite_version`
    - Login-Rate-Limit-Transients mit Präfix `sm_login_attempts_`
