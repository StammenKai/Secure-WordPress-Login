# SM Security Suite

![WordPress](https://img.shields.io/badge/WordPress-6.4%2B-21759B?logo=wordpress&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-8.2%2B-777BB4?logo=php&logoColor=white)
![License](https://img.shields.io/badge/License-GPLv2%2B-green)

WordPress-Login absichern, Angriffe ausbremsen und moderne Security Header aktivieren, ohne dass Nutzer an der `wp-config.php` arbeiten muessen.

SM Security Suite kombiniert Login-Schutz und Header-Hardening in einem Plugin mit Admin-Einstellungsseite. Fuer einfache Deployments sind die urspruenglichen MU-Plugin-Dateien ebenfalls enthalten.

## Warum dieses Plugin?

Viele WordPress-Sicherheitsplugins sind fuer kleine Projekte zu gross, zu komplex oder zu intransparent. SM Security Suite konzentriert sich auf die Punkte, die in der Praxis sofort helfen:

- Brute-Force-Angriffe am Login abbremsen
- die Standard-Login-URL optional verstecken
- wichtige Browser-Sicherheitsheader setzen
- CSP sicher zuerst im Report-Only-Modus einfuehren
- Einstellungen im Backend pflegen statt in Konfigurationsdateien

## Kernfunktionen

- Login-Rate-Limiting ueber WordPress-Transients
- Optionaler Custom Login-Slug
- Blockierung direkter `wp-login.php`-Aufrufe bei aktivem Slug
- HTTP Security Header fuer Frontend und Admin
- Content-Security-Policy mit Report-Only-Workflow
- Backend-Einstellungen unter Einstellungen > SM Security Suite
- DSGVO-freundliche Speicherung von Login-Versuchen via gehashter IP
- Aktivierung, Deaktivierung und Uninstall nach WordPress-Best-Practice

## Empfohlene Nutzung

Fuer fast alle Installationen ist die Standard-Plugin-Variante die richtige Wahl:

- Plugin-Ordner: `sm-security-suite/`
- Hauptdatei: `sm-security-suite/sm-security-suite.php`

Diese Variante bietet:
- Backend-Konfiguration ohne Dateizugriff
- sauberen Plugin-Lifecycle
- bessere Wartbarkeit fuer Kundenprojekte und Agentur-Deployments

## Schnellstart

1. Den Ordner `sm-security-suite` nach `wp-content/plugins/` kopieren.
2. Das Plugin im WordPress-Backend aktivieren.
3. Einmal Einstellungen > Permalinks speichern.
4. Unter Einstellungen > SM Security Suite die gewuenschten Werte setzen.

## Im Backend konfigurierbar

- Maximale Login-Versuche
- Sperrdauer in Sekunden
- Custom Login-Slug
- CSP Report-Only
- HSTS max-age
- Permissions-Policy

Optional koennen die gleichen Werte weiterhin ueber Konstanten in der `wp-config.php` gesetzt werden. Konstanten haben bewusst Vorrang vor den gespeicherten Einstellungen.

## Varianten im Repository

### Standard-Plugin

Pfad: `sm-security-suite/`

Empfohlen fuer normale WordPress-Installationen, Deployment per ZIP und Kundenprojekte.

### MU-Plugin-Dateien

Dateien:
- `sm-login-protection.php`
- `sm-security-headers.php`

Geeignet fuer Setups, in denen Sicherheitsfunktionen als Must-Use-Plugins direkt unter `wp-content/mu-plugins/` laufen sollen.

## Projektstruktur

```text
WP-Login/
├── README.md
├── INSTALLATION.md
├── docs/
│   └── USER-DOKUMENTATION.md
├── sm-login-protection.php
├── sm-security-headers.php
├── sm-security-suite/
│   ├── sm-security-suite.php
│   ├── readme.txt
│   ├── uninstall.php
│   └── includes/
│       ├── admin-settings.php
│       ├── login-protection.php
│       └── security-headers.php
└── sm-security-suite.zip
```

## Sicherheitshinweise

- Nach einer Aenderung des Login-Slugs sollten Permalinks neu gespeichert werden.
- Nach Login-Slug-Aenderungen sollten Cache, Proxy und CDN geleert werden.
- CSP sollte zuerst im Report-Only-Modus beobachtet und erst spaeter erzwungen werden.
- Vor dem Live-Einsatz empfiehlt sich ein Test in Staging.

## Dokumentation

Weiterfuehrende Dokumente im Repository:

- `INSTALLATION.md`
- `docs/USER-DOKUMENTATION.md`
- `sm-security-suite/readme.txt`

## Gespeicherte Daten

Beim Standard-Plugin werden in WordPress unter anderem diese Eintraege genutzt:

- `sm_security_suite_settings`
- `sm_security_suite_version`
- Rate-Limit-Transients mit dem Prefix `sm_login_attempts_`

Die IP-Adresse wird dabei nicht im Klartext gespeichert, sondern als gesalzener SHA-256-Hash verarbeitet.

## Deinstallation

Beim Loeschen des Standard-Plugins werden entfernt:

- `sm_security_suite_version`
- `sm_security_suite_settings`
- Rate-Limit-Transients mit dem Prefix `sm_login_attempts_`

## Geeignet fuer

- Agenturen mit mehreren WordPress-Installationen
- Kundenprojekte mit einfacher Backend-Konfiguration
- WordPress-Setups, die eine schlanke Sicherheitsbasis brauchen
- Installationen, bei denen Login-Schutz und Header-Hardening bewusst getrennt von grossen Security-Suiten gehalten werden sollen

## Status

Entwickelt fuer WordPress 6.4+ und PHP 8.2+.

Wenn du dieses Repository fuer reale Projekte einsetzt, ist die Standard-Plugin-Variante der sinnvollste Distributionsweg.