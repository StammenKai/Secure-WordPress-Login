<?php
/**
 * Plugin Name: SM Login Protection
 * Description: Schützt wp-login.php durch Rate Limiting (Brute-Force) und Custom Login URL.
 * Version:     1.0.1
 * Author:      StammenMedia
 * License:     GPL-2.0-or-later
 * Text Domain: sm-login-protection
 *
 * Mu-Plugin – Ablage in wp-content/mu-plugins/sm-login-protection.php
 *
 * ═══════════════════════════════════════════════════════════════════
 * KONFIGURATION – diese Konstanten können in wp-config.php
 * überschrieben werden, um pro Site individuelle Werte zu setzen.
 * ═══════════════════════════════════════════════════════════════════
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/* ---------- Konfigurierbare Konstanten ---------- */

// Maximale Login-Versuche bevor Sperre greift.
if ( ! defined( 'SM_LOGIN_MAX_ATTEMPTS' ) ) {
    define( 'SM_LOGIN_MAX_ATTEMPTS', 5 );
}

// Sperrdauer in Sekunden (900 = 15 Minuten).
if ( ! defined( 'SM_LOGIN_LOCKOUT_DURATION' ) ) {
    define( 'SM_LOGIN_LOCKOUT_DURATION', 900 );
}

// Custom Login-Slug (z. B. 'mein-login' → example.de/mein-login).
// Auf leer lassen ('') um die Funktion zu deaktivieren.
if ( ! defined( 'SM_LOGIN_SLUG' ) ) {
    define( 'SM_LOGIN_SLUG', 'mein-login' );
}

// Transient-Präfix für Datenbank-Keys.
if ( ! defined( 'SM_LOGIN_TRANSIENT_PREFIX' ) ) {
    define( 'SM_LOGIN_TRANSIENT_PREFIX', 'sm_login_attempts_' );
}


/* ═══════════════════════════════════════════════════════════════════
 * 1. RATE LIMITING (Brute-Force-Schutz)
 *
 * Nutzt WordPress-Transients statt eigener DB-Tabelle.
 * Speichert Versuche pro IP-Adresse.
 * DSGVO: IP wird nur als SHA-256-Hash gespeichert.
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * Ermittelt die Client-IP unter Berücksichtigung von Reverse Proxies.
 * Gibt einen SHA-256-Hash zurück (DSGVO-konform – keine Klartext-IP).
 *
 * @return string SHA-256-Hash der IP.
 */
function sm_login_get_ip_hash(): string {
    $ip = '';

    // IONOS/envoy setzt ggf. X-Forwarded-For.
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        // Erste IP in der Kette ist die echte Client-IP.
        $forwarded = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
        $ip        = trim( $forwarded[0] );
    }

    if ( empty( $ip ) && ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
    }

    if ( empty( $ip ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' ) );
    }

    // Validierung: Muss eine gültige IPv4/IPv6-Adresse sein.
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        $ip = '0.0.0.0';
    }

    // DSGVO: Nur Hash speichern, nie die Klartext-IP.
    return hash( 'sha256', $ip . wp_salt( 'auth' ) );
}

/**
 * Gibt die Anzahl der fehlgeschlagenen Login-Versuche zurück.
 *
 * @param string $ip_hash SHA-256-Hash der Client-IP.
 * @return int Anzahl fehlgeschlagener Versuche.
 */
function sm_login_get_attempts( string $ip_hash ): int {
    $transient_key = SM_LOGIN_TRANSIENT_PREFIX . substr( $ip_hash, 0, 40 );
    $attempts      = get_transient( $transient_key );
    return is_numeric( $attempts ) ? (int) $attempts : 0;
}

/**
 * Inkrementiert den Fehlversuchs-Zähler.
 *
 * @param string $ip_hash SHA-256-Hash der Client-IP.
 */
function sm_login_increment_attempts( string $ip_hash ): void {
    $transient_key = SM_LOGIN_TRANSIENT_PREFIX . substr( $ip_hash, 0, 40 );
    $attempts      = sm_login_get_attempts( $ip_hash ) + 1;
    set_transient( $transient_key, $attempts, SM_LOGIN_LOCKOUT_DURATION );
}

/**
 * Setzt den Zähler nach erfolgreichem Login zurück.
 *
 * @param string $ip_hash SHA-256-Hash der Client-IP.
 */
function sm_login_reset_attempts( string $ip_hash ): void {
    $transient_key = SM_LOGIN_TRANSIENT_PREFIX . substr( $ip_hash, 0, 40 );
    delete_transient( $transient_key );
}

/**
 * Hook: Prüft vor der Authentifizierung, ob die IP gesperrt ist.
 *
 * @param WP_User|WP_Error|null $user     Aktueller Auth-Status.
 * @param string                $username Eingegebener Benutzername.
 * @return WP_User|WP_Error
 */
function sm_login_check_lockout( $user, string $username ) {
    // Leere Benutzernamen ignorieren (verhindert Sperre bei leerem Formular).
    if ( empty( $username ) ) {
        return $user;
    }

    $ip_hash  = sm_login_get_ip_hash();
    $attempts = sm_login_get_attempts( $ip_hash );

    if ( $attempts >= SM_LOGIN_MAX_ATTEMPTS ) {
        $minutes = ceil( SM_LOGIN_LOCKOUT_DURATION / 60 );

        return new WP_Error(
            'sm_login_locked',
            sprintf(
                /* translators: %d: Sperrdauer in Minuten */
                __( 'Zu viele fehlgeschlagene Anmeldeversuche. Bitte versuche es in %d Minuten erneut.', 'sm-login-protection' ),
                $minutes
            )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'sm_login_check_lockout', 30, 2 );

/**
 * Hook: Zählt fehlgeschlagene Login-Versuche.
 *
 * @param string   $username Benutzername.
 * @param WP_Error $error    Fehler-Objekt.
 */
function sm_login_on_failed( string $username, WP_Error $error ): void {
    // Nur echte Auth-Fehler zählen, nicht unsere eigene Sperre.
    if ( $error->get_error_code() === 'sm_login_locked' ) {
        return;
    }
    sm_login_increment_attempts( sm_login_get_ip_hash() );
}
add_action( 'wp_login_failed', 'sm_login_on_failed', 10, 2 );

/**
 * Hook: Setzt den Zähler nach erfolgreichem Login zurück.
 *
 * @param string  $user_login Benutzername.
 * @param WP_User $user       User-Objekt.
 */
function sm_login_on_success( string $user_login, WP_User $user ): void {
    sm_login_reset_attempts( sm_login_get_ip_hash() );
}
add_action( 'wp_login', 'sm_login_on_success', 10, 2 );


/* ═══════════════════════════════════════════════════════════════════
 * 2. CUSTOM LOGIN URL
 *
 * Leitet /wp-login.php auf 404 um, es sei denn der Aufruf erfolgt
 * über den Custom-Slug. Interne WordPress-Redirects (z. B. von
 * wp-admin bei nicht eingeloggten Usern) werden korrekt behandelt.
 * ═══════════════════════════════════════════════════════════════════ */

if ( SM_LOGIN_SLUG !== '' ) {

    /**
     * Registriert den Custom Login-Slug als Rewrite-Rule.
     */
    function sm_login_add_rewrite(): void {
        add_rewrite_rule(
            '^' . preg_quote( SM_LOGIN_SLUG, '/' ) . '/?$',
            'wp-login.php',
            'top'
        );
    }
    add_action( 'init', 'sm_login_add_rewrite' );

    /**
     * Registriert eine Query-Variable, um den Custom-Slug zu erkennen.
     *
     * @param array $vars Vorhandene Query-Vars.
     * @return array Erweiterte Query-Vars.
     */
    function sm_login_query_vars( array $vars ): array {
        $vars[] = 'sm_custom_login';
        return $vars;
    }
    add_filter( 'query_vars', 'sm_login_query_vars' );

    /**
     * Setzt ein Cookie/Flag, wenn der Zugriff über den Custom-Slug erfolgt.
     */
    function sm_login_set_access_flag(): void {
        $request_uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );
        $slug        = '/' . SM_LOGIN_SLUG;

        if ( str_starts_with( parse_url( $request_uri, PHP_URL_PATH ) ?? '', $slug ) ) {
            // Nonce als einmaliges Zugangstoken setzen (60 Sekunden gültig).
            $nonce = wp_create_nonce( 'sm_login_access' );
            setcookie( 'sm_login_token', $nonce, [
                'expires'  => time() + 60,
                'path'     => '/',
                'secure'   => is_ssl(),
                'httponly'  => true,
                'samesite' => 'Strict',
            ] );
        }
    }
    add_action( 'init', 'sm_login_set_access_flag', 1 );

    /**
     * Blockiert direkten Zugriff auf wp-login.php ohne gültiges Token.
     * Erlaubt: POST-Requests (für Logouts, Passwort-Resets etc.),
     *          AJAX/Cron/CLI-Kontexte und Zugriff mit gültigem Cookie.
     */
    function sm_login_protect_wplogin(): void {
        // Nur für wp-login.php relevant.
        if ( ! isset( $GLOBALS['pagenow'] ) || $GLOBALS['pagenow'] !== 'wp-login.php' ) {
            return;
        }

        // CLI, AJAX, Cron → nicht blockieren.
        if ( defined( 'WP_CLI' ) || wp_doing_ajax() || wp_doing_cron() ) {
            return;
        }

        // POST-Requests durchlassen (Login-Formular, Passwort-Reset, Logout).
        if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
            return;
        }

        // Spezielle Aktionen erlauben (Passwort-Reset, E-Mail-Bestätigung, Logout).
        $allowed_actions = [ 'logout', 'lostpassword', 'rp', 'resetpass', 'postpass', 'confirmaction' ];
        if ( isset( $_GET['action'] ) && in_array( sanitize_key( $_GET['action'] ), $allowed_actions, true ) ) {
            return;
        }

        // Prüfe ob Zugangs-Cookie vorhanden und gültig ist.
        if ( isset( $_COOKIE['sm_login_token'] ) && wp_verify_nonce( $_COOKIE['sm_login_token'], 'sm_login_access' ) ) {
            return;
        }

        // Kein gültiger Zugang → 404.
        global $wp_query;
        if ( $wp_query ) {
            $wp_query->set_404();
        }
        status_header( 404 );
        nocache_headers();

        // WordPress 404-Template nutzen, falls vorhanden.
        $template = get_404_template();
        if ( $template ) {
            include $template;
        } else {
            wp_die(
                __( 'Diese Seite existiert nicht.', 'sm-login-protection' ),
                __( 'Nicht gefunden', 'sm-login-protection' ),
                [ 'response' => 404 ]
            );
        }
        exit;
    }
    add_action( 'login_init', 'sm_login_protect_wplogin', 1 );

    /**
     * Passt die Login-URL in WordPress an (z. B. für wp_login_url()).
     *
     * @param string $login_url Originale Login-URL.
     * @return string Angepasste Login-URL.
     */
    function sm_login_custom_url( string $login_url ): string {
        return str_replace( 'wp-login.php', SM_LOGIN_SLUG, $login_url );
    }
    add_filter( 'login_url', 'sm_login_custom_url' );

    /**
     * Leitet /wp-admin/ bei nicht eingeloggten Usern auf den Custom-Slug um.
     */
    function sm_login_redirect_wpadmin(): void {
        if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() ) {
            $redirect_to = isset( $_SERVER['REQUEST_URI'] )
                ? urlencode( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) )
                : '';
            wp_safe_redirect( home_url( SM_LOGIN_SLUG . '?redirect_to=' . $redirect_to ) );
            exit;
        }
    }
    add_action( 'admin_init', 'sm_login_redirect_wpadmin' );

    /**
     * Flusht Rewrite-Rules einmalig bei Aktivierung.
     * Da Mu-Plugins keine register_activation_hook haben,
     * nutzen wir einen Transient-Check.
     */
    function sm_login_maybe_flush_rules(): void {
        if ( ! get_transient( 'sm_login_rules_flushed' ) ) {
            flush_rewrite_rules( false );
            set_transient( 'sm_login_rules_flushed', true, DAY_IN_SECONDS );
        }
    }
    add_action( 'init', 'sm_login_maybe_flush_rules', 99 );
}
