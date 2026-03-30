<?php
/**
 * Security Header und CSP-Handling.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Sendet alle Security-Header.
 */
function sm_security_send_headers(): void {
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
 * @return array<string, string>
 */
function sm_security_build_headers(): array {
    $headers = [];
    $permissions_policy = (string) sm_security_suite_get_setting( 'permissions_policy' );
    $hsts_max_age       = (int) sm_security_suite_get_setting( 'hsts_max_age' );
    $csp_report_only    = (bool) sm_security_suite_get_setting( 'csp_report_only' );

    $headers['X-Frame-Options']            = 'SAMEORIGIN';
    $headers['X-Content-Type-Options']     = 'nosniff';
    $headers['Referrer-Policy']            = 'strict-origin-when-cross-origin';
    $headers['X-XSS-Protection']           = '1; mode=block';
    $headers['Permissions-Policy']         = $permissions_policy;
    $headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    $headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none';
    $headers['Cross-Origin-Resource-Policy'] = 'cross-origin';

    if ( $hsts_max_age > 0 && is_ssl() ) {
        $headers['Strict-Transport-Security'] = sprintf(
            'max-age=%d; includeSubDomains; preload',
            $hsts_max_age
        );
    }

    $csp = sm_security_build_csp();

    if ( $csp_report_only ) {
        $headers['Content-Security-Policy-Report-Only'] = $csp;
    } else {
        $headers['Content-Security-Policy'] = $csp;
    }

    /**
     * Filter: Erlaubt das Hinzufuegen/Entfernen von Headern pro Site.
     *
     * @param array<string, string> $headers Security-Header.
     */
    return apply_filters( 'sm_security_headers', $headers );
}

/**
 * Baut die Content-Security-Policy.
 *
 * @return string CSP-Direktiven.
 */
function sm_security_build_csp(): string {
    $is_admin = is_admin();

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

    if ( $is_admin ) {
        $directives[] = "script-src 'self' 'unsafe-inline' 'unsafe-eval'";
        $directives[] = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com";
    } else {
        $directives[] = "script-src 'self' 'unsafe-inline'";
        $directives[] = "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com";
    }

    /**
     * Filter: Erlaubt das Anpassen der CSP-Direktiven pro Site.
     *
     * @param array<int, string> $directives CSP-Direktiven.
     */
    $directives = apply_filters( 'sm_csp_directives', $directives );

    return implode( '; ', $directives );
}

/**
 * Registriert den CSP-Report-Endpoint.
 */
function sm_security_register_csp_endpoint(): void {
    if ( ! (bool) sm_security_suite_get_setting( 'csp_report_only' ) ) {
        return;
    }

    register_rest_route( 'sm-security/v1', '/csp-report', [
        'methods'             => 'POST',
        'callback'            => 'sm_security_handle_csp_report',
        'permission_callback' => '__return_true',
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

/**
 * Zeigt Admin-Notice wenn CSP im Report-Only-Modus ist.
 */
function sm_security_admin_notice(): void {
    if ( ! (bool) sm_security_suite_get_setting( 'csp_report_only' ) || ! current_user_can( 'manage_options' ) ) {
        return;
    }

    if ( ! function_exists( 'get_current_screen' ) ) {
        return;
    }

    $screen = get_current_screen();
    if ( ! $screen || $screen->id !== 'dashboard' ) {
        return;
    }

    echo '<div class="notice notice-info is-dismissible">';
    echo '<p><strong>SM Security Suite:</strong> ';
    echo esc_html__( 'Content-Security-Policy laeuft im Report-Only-Modus. Pruefe das Error-Log auf Violations, bevor du den Modus auf enforce umstellst.', 'sm-security-suite' );
    echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=sm-security-suite' ) ) . '">';
    echo esc_html__( 'Jetzt in den Einstellungen anpassen', 'sm-security-suite' );
    echo '</a></p>';
    echo '</div>';
}
add_action( 'admin_notices', 'sm_security_admin_notice' );
