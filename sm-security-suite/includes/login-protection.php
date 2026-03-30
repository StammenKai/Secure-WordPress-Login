<?php
/**
 * Login-Schutz: Rate Limiting und Custom Login URL.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Transient-Praefix fuer Datenbank-Keys.
if ( ! defined( 'SM_LOGIN_TRANSIENT_PREFIX' ) ) {
    define( 'SM_LOGIN_TRANSIENT_PREFIX', 'sm_login_attempts_' );
}

/**
 * Ermittelt die Client-IP unter Beruecksichtigung von Reverse Proxies.
 * Gibt einen SHA-256-Hash zurueck (DSGVO-konform, keine Klartext-IP).
 *
 * @return string SHA-256-Hash der IP.
 */
function sm_login_get_ip_hash(): string {
    $ip = '';

    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        $forwarded = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
        $ip        = trim( $forwarded[0] );
    }

    if ( empty( $ip ) && ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
    }

    if ( empty( $ip ) ) {
        $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' ) );
    }

    if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
        $ip = '0.0.0.0';
    }

    return hash( 'sha256', $ip . wp_salt( 'auth' ) );
}

/**
 * Gibt die Anzahl der fehlgeschlagenen Login-Versuche zurueck.
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
 * Inkrementiert den Fehlversuchs-Zaehler.
 *
 * @param string $ip_hash SHA-256-Hash der Client-IP.
 */
function sm_login_increment_attempts( string $ip_hash ): void {
    $transient_key = SM_LOGIN_TRANSIENT_PREFIX . substr( $ip_hash, 0, 40 );
    $attempts      = sm_login_get_attempts( $ip_hash ) + 1;
    $lockout       = (int) sm_security_suite_get_setting( 'login_lockout_duration' );

    set_transient( $transient_key, $attempts, $lockout );
}

/**
 * Setzt den Zaehler nach erfolgreichem Login zurueck.
 *
 * @param string $ip_hash SHA-256-Hash der Client-IP.
 */
function sm_login_reset_attempts( string $ip_hash ): void {
    $transient_key = SM_LOGIN_TRANSIENT_PREFIX . substr( $ip_hash, 0, 40 );
    delete_transient( $transient_key );
}

/**
 * Prueft vor der Authentifizierung, ob die IP gesperrt ist.
 *
 * @param WP_User|WP_Error|null $user Aktueller Auth-Status.
 * @param string                $username Eingegebener Benutzername.
 * @return WP_User|WP_Error|null
 */
function sm_login_check_lockout( $user, string $username ) {
    if ( empty( $username ) ) {
        return $user;
    }

    $ip_hash  = sm_login_get_ip_hash();
    $attempts = sm_login_get_attempts( $ip_hash );
    $max      = (int) sm_security_suite_get_setting( 'login_max_attempts' );
    $lockout  = (int) sm_security_suite_get_setting( 'login_lockout_duration' );

    if ( $attempts >= $max ) {
        $minutes = (int) ceil( $lockout / 60 );

        return new WP_Error(
            'sm_login_locked',
            sprintf(
                /* translators: %d: Sperrdauer in Minuten */
                __( 'Zu viele fehlgeschlagene Anmeldeversuche. Bitte versuche es in %d Minuten erneut.', 'sm-security-suite' ),
                $minutes
            )
        );
    }

    return $user;
}
add_filter( 'authenticate', 'sm_login_check_lockout', 30, 2 );

/**
 * Zaehlt fehlgeschlagene Login-Versuche.
 *
 * @param string   $username Benutzername.
 * @param WP_Error $error Fehler-Objekt.
 */
function sm_login_on_failed( string $username, WP_Error $error ): void {
    if ( $error->get_error_code() === 'sm_login_locked' ) {
        return;
    }

    sm_login_increment_attempts( sm_login_get_ip_hash() );
}
add_action( 'wp_login_failed', 'sm_login_on_failed', 10, 2 );

/**
 * Setzt den Zaehler nach erfolgreichem Login zurueck.
 *
 * @param string  $user_login Benutzername.
 * @param WP_User $user User-Objekt.
 */
function sm_login_on_success( string $user_login, WP_User $user ): void {
    sm_login_reset_attempts( sm_login_get_ip_hash() );
}
add_action( 'wp_login', 'sm_login_on_success', 10, 2 );

/**
 * Prueft, ob der Custom-Slug technisch sicher nutzbar ist.
 *
 * Bei Plain-Permalinks funktionieren Rewrite-Regeln fuer den Slug nicht
 * zuverlaessig. In dem Fall wird wp-login.php nicht blockiert.
 *
 * @return bool
 */
function sm_login_is_custom_slug_active(): bool {
    $slug = (string) sm_security_suite_get_setting( 'login_slug' );

    if ( '' === $slug ) {
        return false;
    }

    $permalink_structure = (string) get_option( 'permalink_structure', '' );

    return '' !== $permalink_structure;
}

/**
 * Ermittelt den normalisierten Request-Pfad relativ zur Site-Basis.
 *
 * @return string Pfad ohne fuehrenden Slash, z. B. "mein-login".
 */
function sm_login_get_request_path(): string {
    $request_uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );
    $path        = (string) parse_url( $request_uri, PHP_URL_PATH );

    $home_path = (string) parse_url( home_url( '/' ), PHP_URL_PATH );
    $home_path = trim( $home_path, '/' );

    $path = trim( $path, '/' );

    if ( '' !== $home_path && str_starts_with( $path, $home_path . '/' ) ) {
        $path = substr( $path, strlen( $home_path ) + 1 );
    } elseif ( $path === $home_path ) {
        $path = '';
    }

    return trim( $path, '/' );
}

/**
 * Leitet den Custom-Slug direkt auf wp-login.php weiter, auch ohne Rewrite.
 */
function sm_login_handle_custom_slug_request(): void {
    if ( ! sm_login_is_custom_slug_active() ) {
        return;
    }

    if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
        return;
    }

    $slug         = trim( (string) sm_security_suite_get_setting( 'login_slug' ), '/' );
    $request_path = sm_login_get_request_path();

    if ( '' === $slug || $request_path !== $slug ) {
        return;
    }

    require ABSPATH . 'wp-login.php';
    exit;
}
add_action( 'init', 'sm_login_handle_custom_slug_request', 0 );

/**
 * Registriert den Custom Login-Slug als Rewrite-Rule.
 */
function sm_login_add_rewrite(): void {
    if ( ! sm_login_is_custom_slug_active() ) {
        return;
    }

    $slug = (string) sm_security_suite_get_setting( 'login_slug' );

    add_rewrite_rule(
        '^' . preg_quote( $slug, '/' ) . '/?$',
        'wp-login.php',
        'top'
    );
}
add_action( 'init', 'sm_login_add_rewrite' );

/**
 * Blockiert direkten Zugriff auf wp-login.php, erlaubt aber den Custom-Slug.
 */
function sm_login_protect_wplogin(): void {
    if ( ! sm_login_is_custom_slug_active() ) {
        return;
    }

    $slug_value = (string) sm_security_suite_get_setting( 'login_slug' );

    if ( ! isset( $GLOBALS['pagenow'] ) || $GLOBALS['pagenow'] !== 'wp-login.php' ) {
        return;
    }

    if ( defined( 'WP_CLI' ) || wp_doing_ajax() || wp_doing_cron() ) {
        return;
    }

    if ( ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) === 'POST' ) {
        return;
    }

    $allowed_actions = [ 'logout', 'lostpassword', 'rp', 'resetpass', 'postpass', 'confirmaction' ];
    if ( isset( $_GET['action'] ) && in_array( sanitize_key( $_GET['action'] ), $allowed_actions, true ) ) {
        return;
    }

    $request_path = sm_login_get_request_path();
    $slug_path    = trim( $slug_value, '/' );

    // Zugriff ueber den konfigurierten Slug ist erlaubt.
    if ( '' !== $slug_path && $request_path === $slug_path ) {
        return;
    }

    global $wp_query;
    if ( $wp_query ) {
        $wp_query->set_404();
    }

    status_header( 404 );
    nocache_headers();

    $template = get_404_template();
    if ( $template ) {
        include $template;
    } else {
        wp_die(
            esc_html__( 'Diese Seite existiert nicht.', 'sm-security-suite' ),
            esc_html__( 'Nicht gefunden', 'sm-security-suite' ),
            [ 'response' => 404 ]
        );
    }

    exit;
}
add_action( 'login_init', 'sm_login_protect_wplogin', 1 );

/**
 * Passt die Login-URL in WordPress an.
 *
 * @param string $login_url Originale Login-URL.
 * @return string Angepasste Login-URL.
 */
function sm_login_custom_url( string $login_url ): string {
    if ( ! sm_login_is_custom_slug_active() ) {
        return $login_url;
    }

    $slug_value = (string) sm_security_suite_get_setting( 'login_slug' );

    return str_replace( 'wp-login.php', $slug_value, $login_url );
}
add_filter( 'login_url', 'sm_login_custom_url' );

/**
 * Leitet wp-admin bei nicht eingeloggten Usern auf den Custom-Slug um.
 */
function sm_login_redirect_wpadmin(): void {
    if ( ! sm_login_is_custom_slug_active() ) {
        return;
    }

    $slug_value = (string) sm_security_suite_get_setting( 'login_slug' );

    if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() ) {
        $redirect_to = isset( $_SERVER['REQUEST_URI'] )
            ? urlencode( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) )
            : '';

        wp_safe_redirect( home_url( $slug_value . '?redirect_to=' . $redirect_to ) );
        exit;
    }
}
add_action( 'admin_init', 'sm_login_redirect_wpadmin', 1 );
