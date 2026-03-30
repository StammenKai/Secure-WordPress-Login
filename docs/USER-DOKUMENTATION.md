# SM Security Suite - User Dokumentation

## 1. Zweck des Plugins

SM Security Suite schuetzt den WordPress-Login und setzt wichtige Security Header.

Enthaltene Funktionen:
- Login-Rate-Limiting gegen Brute-Force-Angriffe
- Optionaler Custom Login-Slug statt direkter Login-URL
- Security Header inklusive Content-Security-Policy (CSP)
- Backend-Einstellungsseite fuer einfache Verwaltung ohne Bearbeitung der wp-config.php

## 2. Voraussetzungen

- WordPress ab 6.4
- PHP ab 8.2
- Admin-Rechte fuer die Plugin-Konfiguration

## 3. Installation als Standard-Plugin

1. Ordner sm-security-suite in wp-content/plugins kopieren.
2. Im WordPress-Backend unter Plugins aktivieren.
3. Danach einmal Einstellungen > Permalinks aufrufen und speichern.

Hinweis:
Der Permalink-Schritt ist empfohlen, damit die Login-Slug-Route sauber registriert ist.

## 4. Wo finde ich die Einstellungen?

Im WordPress-Backend:
- Einstellungen > SM Security Suite

Dort kann alles direkt im Backend gesetzt werden.

## 5. Einstellungen im Detail

### 5.1 Login-Schutz

Maximale Login-Versuche:
- Anzahl erlaubter Fehlversuche pro IP-Hash
- Nach Erreichen wird fuer die definierte Sperrdauer blockiert

Sperrdauer (Sekunden):
- Dauer der Login-Sperre
- Beispiel: 900 = 15 Minuten

Custom Login-Slug:
- Eigener Login-Pfad, z. B. mein-login
- Wenn leer, ist der Custom-Slug deaktiviert

### 5.2 Security Header

CSP Report-Only:
- Aktiviert: CSP wird nur protokolliert, nicht erzwungen
- Deaktiviert: CSP wird aktiv erzwungen

HSTS max-age:
- Dauer in Sekunden, wie lange Browser HTTPS erzwingen
- 0 deaktiviert HSTS

Permissions-Policy:
- Steuerung erlaubter Browser-APIs
- Kann projektspezifisch angepasst werden

## 6. Prioritaet von Einstellungen

Reihenfolge der Prioritaet:
1. Konstanten in wp-config.php
2. Werte aus dem Backend (SM Security Suite Einstellungen)
3. Plugin-Defaults

Das bedeutet:
Wenn eine Konstante in der wp-config.php gesetzt ist, ueberschreibt sie den Backend-Wert.

## 7. Empfohlene Erstkonfiguration

1. CSP Report-Only aktiviert lassen.
2. Einige Tage Logs beobachten.
3. Externe Quellen bei Bedarf via Filter freigeben.
4. Danach CSP auf Enforce umstellen.

Fuer Login-Schutz sinnvoller Start:
- Maximale Login-Versuche: 5
- Sperrdauer: 900
- Custom Login-Slug: eindeutiger Slug ohne Sonderzeichen

## 8. Test-Checkliste nach Einrichtung

Login:
- Eigene Login-URL aufrufen (z. B. /mein-login)
- Erfolgreichen Login pruefen
- Mehrfache Fehlversuche testen, Sperre pruefen

Blockierung:
- Direkter Aufruf von /wp-login.php testen
- Erwartung: geblockt, wenn Custom-Slug aktiv und technisch nutzbar

Header:
- DevTools Network pruefen
- Optional SecurityHeaders.com pruefen

## 9. Troubleshooting

### Problem: Custom Login-Slug liefert 404

Moegliche Ursachen:
- Permalinks nicht neu gespeichert
- Caching/Proxy liefert alte Route
- Slug enthaelt ungeeignete Zeichen
- Alte Plugin-Version ohne Fallback-Logik aktiv

Loesung:
1. Einstellungen > Permalinks speichern
2. Alle Caches leeren (Plugin, Server, CDN)
3. Slug auf einfachen Wert setzen (z. B. mein-login)
4. Plugin-Dateien auf aktuelle Version aktualisieren

### Problem: wp-login.php geblockt, Slug geht nicht

Notfallweg:
1. Per FTP/SFTP den Plugin-Ordner umbenennen, z. B. sm-security-suite-off
2. Dann normal ueber /wp-login.php einloggen
3. Plugin-Dateien aktualisieren
4. Plugin wieder aktivieren
5. Permalinks speichern

### Problem: Einstellungen werden nicht uebernommen

Pruefen:
- Ist eine gleichnamige Konstante in der wp-config.php gesetzt?
- Falls ja, hat diese Vorrang.

## 10. Datenschutz und gespeicherte Daten

Gespeicherte Optionen:
- sm_security_suite_settings
- sm_security_suite_version

Rate-Limit-Daten:
- Als Transients mit Prefix sm_login_attempts_
- IPs werden nicht im Klartext gespeichert, sondern als gesalzener SHA-256-Hash

## 11. Deaktivierung und Deinstallation

Bei Deaktivierung:
- Rewrite-Regeln werden aktualisiert

Bei Deinstallation (Plugin loeschen):
- sm_security_suite_version wird entfernt
- sm_security_suite_settings wird entfernt
- Rate-Limit-Transients mit Prefix sm_login_attempts_ werden entfernt

## 12. Update-Empfehlung

Vor groesseren Updates:
1. Backup erstellen
2. Login mit neuem Slug testen
3. Erst dann auf Live uebernehmen (bei Staging zuerst pruefen)

## 13. Support-Checkliste fuer schnelle Hilfe

Wenn ein Problem gemeldet wird, diese Informationen mitschicken:
- WordPress-Version
- PHP-Version
- Aktiver Login-Slug
- Permalink-Struktur
- Ob Konstanten in wp-config.php gesetzt sind
- Ob ein Cache/CDN aktiv ist
- Exakte Fehlermeldung und URL
