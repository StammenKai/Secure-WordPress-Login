<?php
/**
 * Plugin Name: SM Security Headers
 * Description: Setzt alle empfohlenen HTTP-Security-Header. CSP startet im Report-Only-Modus.
 * Version:     1.0.1
 * Author:      StammenMedia
 * License:     GPL-2.0-or-later
 * Text Domain: sm-security-headers
 *
 * Mu-Plugin – Ablage in wp-content/mu-plugins/sm-security-headers.php
 *
 * ═══════════════════════════════════════════════════════════════════
 * KONFIGURATION – Konstanten können in wp-config.php
 * pro Site überschrieben werden.
 * ═══════════════════════════════════════════════════════════════════
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/* ---------- Konfigurierbare Konstanten ---------- */

// CSP im Report-Only-Modus? true = nur loggen, false = erzwingen.
if ( ! defined( 'SM_CSP_REPORT_ONLY' ) ) {
    define( 'SM_CSP_REPORT_ONLY', true );
}

// HSTS max-age in Sekunden (31536000 = 1 Jahr). Auf 0 setzen um HSTS zu deaktivieren.
if ( ! defined( 'SM_HSTS_MAX_AGE' ) ) {
    define( 'SM_HSTS_MAX_AGE', 31536000 );
}

// Permissions-Policy: Welche Browser-APIs erlaubt sind.
if ( ! defined( 'SM_PERMISSIONS_POLICY' ) ) {
    define( 'SM_PERMISSIONS_POLICY', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()' );
}


/* ═══════════════════════════════════════════════════════════════════
 * SECURITY HEADERS
 *
 * Setzt Header über den 'send_headers'-Hook (WordPress-nativ),
 * damit sie auf allen Seiten greifen – auch im Admin-Bereich.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Sendet alle Security-Header.
 */
function sm_security_send_headers(): void {
    // Nur senden, wenn Header noch nicht gesendet wurden.
    if ( headers_sent() ) {
        return;
    }

    $headers = sm_security_build_headers();

    foreach ( $headers as $name => $value ) {
        header( "{$name}: {$value}" );
    }
}
add_action( 'send_headers', 'sm_security_send_headers', 1 );

/**
 * Baut das Array aller Security-Header.
 *
 * @return array<string, string> Assoziatives Array: Header-Name => Wert.
 */
function sm_security_build_headers(): array {
    $headers = [];

    /* ----------------------------------------------------------
     * 1. X-Frame-Options
     * Verhindert Clickjacking (Einbettung der Seite in iframes).
     * ---------------------------------------------------------- */
    $headers['X-Frame-Options'] = 'SAMEORIGIN';

    /* ----------------------------------------------------------
     * 2. X-Content-Type-Options
     * Verhindert MIME-Type-Sniffing.
     * ---------------------------------------------------------- */
    $headers['X-Content-Type-Options'] = 'nosniff';

    /* ----------------------------------------------------------
     * 3. Referrer-Policy
     * Sendet den Referrer nur bei same-origin Requests vollständig.
     * Cross-origin: nur Origin (ohne Pfad).
     * DSGVO-relevant: minimiert übergebene Daten.
     * ---------------------------------------------------------- */
    $headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';

    /* ----------------------------------------------------------
     * 4. X-XSS-Protection
     * Legacy-Header, wird von modernen Browsern ignoriert,
     * schadet aber nicht und schützt ältere Browser.
     * ---------------------------------------------------------- */
    $headers['X-XSS-Protection'] = '1; mode=block';

    /* ----------------------------------------------------------
     * 5. Strict-Transport-Security (HSTS)
     * Erzwingt HTTPS für alle zukünftigen Aufrufe.
     * ACHTUNG: Erst aktivieren wenn SSL sicher funktioniert!
     * ---------------------------------------------------------- */
    if ( SM_HSTS_MAX_AGE > 0 && is_ssl() ) {
        $headers['Strict-Transport-Security'] = sprintf(
            'max-age=%d; includeSubDomains; preload',
            SM_HSTS_MAX_AGE
        );
    }

    /* ----------------------------------------------------------
     * 6. Permissions-Policy
     * Deaktiviert nicht benötigte Browser-APIs.
     * interest-cohort=() blockiert FLoC (Google Tracking).
     * ---------------------------------------------------------- */
    $headers['Permissions-Policy'] = SM_PERMISSIONS_POLICY;

    /* ----------------------------------------------------------
     * 7. Cross-Origin-Opener-Policy (COOP)
     * Isoliert das Fenster von Cross-Origin-Popups.
     * ---------------------------------------------------------- */
    $headers['Cross-Origin-Opener-Policy'] = 'same-origin';

    /* ----------------------------------------------------------
     * 8. Cross-Origin-Embedder-Policy (COEP)
     * Verhindert das Laden von Cross-Origin-Ressourcen ohne
     * explizite Erlaubnis. 'unsafe-none' ist sicherer für
     * WordPress, da viele Plugins externe Ressourcen laden.
     * ---------------------------------------------------------- */
    $headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none';

    /* ----------------------------------------------------------
     * 9. Cross-Origin-Resource-Policy (CORP)
     * Erlaubt Cross-Origin-Zugriff auf Ressourcen (nötig für
     * eingebettete Bilder, Fonts, CDNs etc.).
     * ---------------------------------------------------------- */
    $headers['Cross-Origin-Resource-Policy'] = 'cross-origin';

    /* ----------------------------------------------------------
     * 10. Content-Security-Policy
     * Definiert erlaubte Quellen für Scripts, Styles, etc.
     * Startet im Report-Only-Modus zur Analyse!
     * ---------------------------------------------------------- */
    $csp = sm_security_build_csp();

    if ( SM_CSP_REPORT_ONLY ) {
        $headers['Content-Security-Policy-Report-Only'] = $csp;
    } else {
        $headers['Content-Security-Policy'] = $csp;
    }

    /**
     * Filter: Erlaubt das Hinzufügen/Entfernen von Headern pro Site.
     *
     * @param array<string, string> $headers Security-Header.
     */
    return apply_filters( 'sm_security_headers', $headers );
}

/**
 * Baut die Content-Security-Policy.
 *
 * Diese CSP ist bewusst WordPress-kompatibel:
 * - 'unsafe-inline' für Styles (Gutenberg, viele Plugins).
 * - 'unsafe-inline' + 'unsafe-eval' für Scripts im Admin.
 * - Externe Quellen für Fonts (Google Fonts, cdnjs).
 *
 * @return string CSP-Direktiven.
 */
function sm_security_build_csp(): string {
    $is_admin = is_admin();

    // Basis-Direktiven.
    $directives = [
        "default-src 'self'",
        "img-src 'self' data: https:",
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        "connect-src 'self' https:",
        "media-src 'self' https:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
    ];

    // Scripts: Im Admin lockerer (Gutenberg braucht unsafe-eval).
    if ( $is_admin ) {
        $directives[] = "script-src 'self' 'unsafe-inline' 'unsafe-eval'";
        $directives[] = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com";
    } else {
        $directives[] = "script-src 'self' 'unsafe-inline'";
        $directives[] = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com";
    }

    /**
     * Filter: Erlaubt das Anpassen der CSP-Direktiven pro Site.
     * Nützlich wenn ein Plugin eine zusätzliche externe Quelle braucht.
     *
     * Beispiel:
     * add_filter( 'sm_csp_directives', function( $dirs ) {
     *     $dirs[] = "script-src 'self' 'unsafe-inline' https://cdn.example.com";
     *     return $dirs;
     * } );
     *
     * @param array $directives CSP-Direktiven.
     */
    $directives = apply_filters( 'sm_csp_directives', $directives );

    return implode( '; ', $directives );
}


/* ═══════════════════════════════════════════════════════════════════
 * REST-API: CSP-Violations-Endpoint (optional)
 *
 * Wenn SM_CSP_REPORT_ONLY aktiv ist, können Browser Verstöße
 * an /wp-json/sm-security/v1/csp-report melden.
 * Die Reports werden im Error-Log gespeichert.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Registriert den CSP-Report-Endpoint.
 */
function sm_security_register_csp_endpoint(): void {
    if ( ! SM_CSP_REPORT_ONLY ) {
        return;
    }

    register_rest_route( 'sm-security/v1', '/csp-report', [
        'methods'             => 'POST',
        'callback'            => 'sm_security_handle_csp_report',
        'permission_callback' => '__return_true', // Öffentlich, da Browser-Reports.
    ] );
}
add_action( 'rest_api_init', 'sm_security_register_csp_endpoint' );

/**
 * Verarbeitet eingehende CSP-Violation-Reports.
 *
 * @param WP_REST_Request $request Request-Objekt.
 * @return WP_REST_Response
 */
function sm_security_handle_csp_report( WP_REST_Request $request ): WP_REST_Response {
    $body = $request->get_body();
    $data = json_decode( $body, true );

    if ( ! empty( $data['csp-report'] ) ) {
        // DSGVO: Nur die Direktive und blockierte URI loggen, keine IP.
        $report = [
            'violated-directive' => sanitize_text_field( $data['csp-report']['violated-directive'] ?? '' ),
            'blocked-uri'        => esc_url_raw( $data['csp-report']['blocked-uri'] ?? '' ),
            'document-uri'       => esc_url_raw( $data['csp-report']['document-uri'] ?? '' ),
            'timestamp'          => current_time( 'mysql' ),
        ];

        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
        error_log( '[SM Security] CSP Violation: ' . wp_json_encode( $report ) );
    }

    return new WP_REST_Response( null, 204 );
}


/* ═══════════════════════════════════════════════════════════════════
 * ADMIN-HINWEIS: CSP Report-Only aktiv
 *
 * Zeigt einen dezenten Hinweis im Admin-Dashboard, solange
 * CSP im Report-Only-Modus läuft.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Zeigt Admin-Notice wenn CSP im Report-Only-Modus ist.
 */
function sm_security_admin_notice(): void {
    if ( ! SM_CSP_REPORT_ONLY || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $screen = get_current_screen();
    if ( ! $screen || $screen->id !== 'dashboard' ) {
        return;
    }

    echo '<div class="notice notice-info is-dismissible">';
    echo '<p><strong>SM Security Headers:</strong> ';
    echo esc_html__( 'Content-Security-Policy läuft im Report-Only-Modus. Prüfe das Error-Log auf Violations, bevor du den Modus auf "enforce" umstellst.', 'sm-security-headers' );
    echo ' <code>define( \'SM_CSP_REPORT_ONLY\', false );</code></p>';
    echo '</div>';
}
add_action( 'admin_notices', 'sm_security_admin_notice' );
