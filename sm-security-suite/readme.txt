=== SM Security Suite ===
Contributors: StammenMedia
Tags: security, login, brute force, headers, csp, hardening
Requires at least: 6.4
Tested up to: 6.5
Requires PHP: 8.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

SM Security Suite schuetzt WordPress mit Login-Rate-Limiting, Custom Login URL und modernen HTTP Security Headern inklusive CSP Report-Only Workflow.

== Description ==

SM Security Suite kombiniert zwei Sicherheitsbereiche in einem Plugin:

1. Login-Schutz
- Brute-Force-Rate-Limiting ueber WordPress Transients
- DSGVO-freundlich: Es wird nur ein gesalzener SHA-256-Hash der IP verwendet
- Optionaler Custom Login Slug statt direktem Zugriff auf wp-login.php

2. Security Header
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- X-XSS-Protection (Legacy)
- Strict-Transport-Security (HSTS)
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy
- Content-Security-Policy (zunaechst Report-Only)

Das Plugin ist fuer produktive WordPress-Installationen gedacht, bei denen Sicherheit und pragmatische Kompatibilitaet mit typischen Plugins wichtig sind.

== Installation ==

1. Ordner sm-security-suite in wp-content/plugins/ hochladen.
2. Plugin in WordPress unter Plugins aktivieren.
3. Optional: Login-Einstellungen im Admin unter Einstellungen > SM Security Suite anpassen.
4. Optional: Header-Einstellungen (CSP Report-Only, HSTS, Permissions-Policy) im selben Screen anpassen.
4. Optional: Einstellungen in wp-config.php ueberschreiben (Konstanten haben Vorrang).

Beispielkonstanten:

- SM_LOGIN_MAX_ATTEMPTS (Standard: 5)
- SM_LOGIN_LOCKOUT_DURATION (Standard: 900 Sekunden)
- SM_LOGIN_SLUG (Standard: mein-login, leer = deaktiviert)
- SM_CSP_REPORT_ONLY (Standard: true)
- SM_HSTS_MAX_AGE (Standard: 31536000)
- SM_PERMISSIONS_POLICY

Nach Aktivierung werden Rewrite-Regeln automatisch geflusht.

== Frequently Asked Questions ==

= Warum startet CSP im Report-Only-Modus? =
Damit potenzielle Blockierungen zuerst beobachtet werden koennen, ohne Frontend oder Admin direkt zu brechen. Nach Auswertung der Logs kann auf Enforce umgestellt werden.

= Kann ich CSP fuer einzelne Dienste erweitern? =
Ja, ueber den Filter sm_csp_directives.

= Was passiert beim Loeschen des Plugins? =
Die Datei uninstall.php entfernt die Plugin-Version-Option und raeumt Login-Rate-Limit-Transients mit dem Prefix sm_login_attempts_ auf.

= Funktioniert das auch ohne Custom Login URL? =
Ja. Setze SM_LOGIN_SLUG auf einen leeren String, um den Slug zu deaktivieren.

= Wo finde ich die Konfiguration ohne wp-config.php? =
Unter Einstellungen > SM Security Suite. Dort koennen maximale Login-Versuche, Sperrdauer, Login-Slug sowie CSP/HSTS/Permissions-Policy direkt im Backend gesetzt werden.

== Screenshots ==

1. Login-Fehlermeldung nach zu vielen Versuchen
2. Admin-Hinweis bei aktivem CSP Report-Only-Modus

== Changelog ==

= 1.0.0 =
* Erstes Release als installierbares Standard-Plugin
* Login-Rate-Limiting mit DSGVO-freundlichem IP-Hash
* Optionaler Custom Login Slug
* Security Header inklusive CSP Report-Only und REST-Endpoint fuer Reports
* Aktivierungs-, Deaktivierungs- und Uninstall-Routinen nach WordPress-Best-Practice

== Upgrade Notice ==

= 1.0.0 =
Erstes stabiles Release. Nach Aktivierung CSP-Reports pruefen, bevor auf Enforce umgestellt wird.
