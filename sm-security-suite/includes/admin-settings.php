<?php
/**
 * Admin-Einstellungen fuer SM Security Suite.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Gibt die Standardwerte fuer Plugin-Einstellungen zurueck.
 *
 * @return array<string, mixed>
 */
function sm_security_suite_get_default_settings(): array {
    return [
        'login_max_attempts'     => 5,
        'login_lockout_duration' => 900,
        'login_slug'             => 'mein-login',
        'csp_report_only'        => 1,
        'hsts_max_age'           => 31536000,
        'permissions_policy'     => 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    ];
}

/**
 * Holt alle Plugin-Einstellungen inklusive Defaults.
 *
 * @return array<string, mixed>
 */
function sm_security_suite_get_settings(): array {
    $saved = get_option( 'sm_security_suite_settings', [] );
    if ( ! is_array( $saved ) ) {
        $saved = [];
    }

    return wp_parse_args( $saved, sm_security_suite_get_default_settings() );
}

/**
 * Liefert einen einzelnen Setting-Wert mit Fallback auf Konstanten.
 *
 * @param string $key Schluessel des Settings.
 * @return mixed
 */
function sm_security_suite_get_setting( string $key ) {
    $constant_map = [
        'login_max_attempts'     => 'SM_LOGIN_MAX_ATTEMPTS',
        'login_lockout_duration' => 'SM_LOGIN_LOCKOUT_DURATION',
        'login_slug'             => 'SM_LOGIN_SLUG',
        'csp_report_only'        => 'SM_CSP_REPORT_ONLY',
        'hsts_max_age'           => 'SM_HSTS_MAX_AGE',
        'permissions_policy'     => 'SM_PERMISSIONS_POLICY',
    ];

    if ( isset( $constant_map[ $key ] ) && defined( $constant_map[ $key ] ) ) {
        return constant( $constant_map[ $key ] );
    }

    $settings = sm_security_suite_get_settings();

    return $settings[ $key ] ?? null;
}

/**
 * Registriert Einstellungen und Felder im Admin.
 */
function sm_security_suite_register_settings(): void {
    register_setting(
        'sm_security_suite_settings_group',
        'sm_security_suite_settings',
        [
            'type'              => 'array',
            'sanitize_callback' => 'sm_security_suite_sanitize_settings',
            'default'           => sm_security_suite_get_default_settings(),
        ]
    );

    add_settings_section(
        'sm_security_suite_login_section',
        __( 'Login-Schutz', 'sm-security-suite' ),
        'sm_security_suite_render_login_section',
        'sm-security-suite'
    );

    add_settings_field(
        'login_max_attempts',
        __( 'Maximale Login-Versuche', 'sm-security-suite' ),
        'sm_security_suite_render_max_attempts_field',
        'sm-security-suite',
        'sm_security_suite_login_section'
    );

    add_settings_field(
        'login_lockout_duration',
        __( 'Sperrdauer (Sekunden)', 'sm-security-suite' ),
        'sm_security_suite_render_lockout_duration_field',
        'sm-security-suite',
        'sm_security_suite_login_section'
    );

    add_settings_field(
        'login_slug',
        __( 'Custom Login-Slug', 'sm-security-suite' ),
        'sm_security_suite_render_login_slug_field',
        'sm-security-suite',
        'sm_security_suite_login_section'
    );

    add_settings_section(
        'sm_security_suite_headers_section',
        __( 'Security Header', 'sm-security-suite' ),
        'sm_security_suite_render_headers_section',
        'sm-security-suite'
    );

    add_settings_field(
        'csp_report_only',
        __( 'CSP Report-Only', 'sm-security-suite' ),
        'sm_security_suite_render_csp_report_only_field',
        'sm-security-suite',
        'sm_security_suite_headers_section'
    );

    add_settings_field(
        'hsts_max_age',
        __( 'HSTS max-age', 'sm-security-suite' ),
        'sm_security_suite_render_hsts_max_age_field',
        'sm-security-suite',
        'sm_security_suite_headers_section'
    );

    add_settings_field(
        'permissions_policy',
        __( 'Permissions-Policy', 'sm-security-suite' ),
        'sm_security_suite_render_permissions_policy_field',
        'sm-security-suite',
        'sm_security_suite_headers_section'
    );
}
add_action( 'admin_init', 'sm_security_suite_register_settings' );

/**
 * Fuegt die Einstellungsseite unter "Einstellungen" hinzu.
 */
function sm_security_suite_add_settings_page(): void {
    add_options_page(
        __( 'SM Security Suite', 'sm-security-suite' ),
        __( 'SM Security Suite', 'sm-security-suite' ),
        'manage_options',
        'sm-security-suite',
        'sm_security_suite_render_settings_page'
    );
}
add_action( 'admin_menu', 'sm_security_suite_add_settings_page' );

/**
 * Sanitizer fuer gespeicherte Optionen.
 *
 * @param array<string, mixed> $input Rohdaten aus dem Formular.
 * @return array<string, mixed>
 */
function sm_security_suite_sanitize_settings( array $input ): array {
    $defaults = sm_security_suite_get_default_settings();
    $output   = $defaults;

    if ( isset( $input['login_max_attempts'] ) ) {
        $output['login_max_attempts'] = max( 1, absint( $input['login_max_attempts'] ) );
    }

    if ( isset( $input['login_lockout_duration'] ) ) {
        $output['login_lockout_duration'] = max( 60, absint( $input['login_lockout_duration'] ) );
    }

    if ( isset( $input['login_slug'] ) ) {
        $slug = sanitize_title( (string) $input['login_slug'] );
        $output['login_slug'] = $slug;
    }

    $output['csp_report_only'] = isset( $input['csp_report_only'] ) ? (int) (bool) $input['csp_report_only'] : 0;

    if ( isset( $input['hsts_max_age'] ) ) {
        $output['hsts_max_age'] = max( 0, absint( $input['hsts_max_age'] ) );
    }

    if ( isset( $input['permissions_policy'] ) ) {
        $output['permissions_policy'] = sanitize_text_field( (string) $input['permissions_policy'] );
    }

    return $output;
}

/**
 * Flusht Rewrite-Regeln, wenn sich der Login-Slug geaendert hat.
 *
 * @param array<string, mixed> $old_value Alter Wert.
 * @param array<string, mixed> $value Neuer Wert.
 */
function sm_security_suite_on_settings_updated( array $old_value, array $value ): void {
    $old_slug = isset( $old_value['login_slug'] ) ? (string) $old_value['login_slug'] : '';
    $new_slug = isset( $value['login_slug'] ) ? (string) $value['login_slug'] : '';

    if ( $old_slug !== $new_slug ) {
        if ( function_exists( 'sm_login_add_rewrite' ) ) {
            sm_login_add_rewrite();
        }

        flush_rewrite_rules( false );
    }
}
add_action( 'update_option_sm_security_suite_settings', 'sm_security_suite_on_settings_updated', 10, 2 );

/**
 * Rendert die Section-Beschreibung.
 */
function sm_security_suite_render_login_section(): void {
    echo '<p>' . esc_html__( 'Konfiguriere den Login-Schutz ohne Anpassung der wp-config.php.', 'sm-security-suite' ) . '</p>';
}

/**
 * Rendert die Header-Section-Beschreibung.
 */
function sm_security_suite_render_headers_section(): void {
    echo '<p>' . esc_html__( 'Konfiguriere Security-Header und CSP direkt im Backend.', 'sm-security-suite' ) . '</p>';
}

/**
 * Rendert Feld fuer maximale Login-Versuche.
 */
function sm_security_suite_render_max_attempts_field(): void {
    $value = (int) sm_security_suite_get_setting( 'login_max_attempts' );

    echo '<input type="number" min="1" step="1" name="sm_security_suite_settings[login_max_attempts]" value="' . esc_attr( (string) $value ) . '" class="small-text" />';
}

/**
 * Rendert Feld fuer Sperrdauer.
 */
function sm_security_suite_render_lockout_duration_field(): void {
    $value = (int) sm_security_suite_get_setting( 'login_lockout_duration' );

    echo '<input type="number" min="60" step="1" name="sm_security_suite_settings[login_lockout_duration]" value="' . esc_attr( (string) $value ) . '" class="small-text" />';
}

/**
 * Rendert Feld fuer Login-Slug.
 */
function sm_security_suite_render_login_slug_field(): void {
    $value = (string) sm_security_suite_get_setting( 'login_slug' );

    echo '<input type="text" name="sm_security_suite_settings[login_slug]" value="' . esc_attr( $value ) . '" class="regular-text" />';
    echo '<p class="description">' . esc_html__( 'Leer lassen, um die Custom-Login-URL zu deaktivieren.', 'sm-security-suite' ) . '</p>';
}

/**
 * Rendert Feld fuer CSP Report-Only.
 */
function sm_security_suite_render_csp_report_only_field(): void {
    $value = (int) sm_security_suite_get_setting( 'csp_report_only' );

    echo '<input type="hidden" name="sm_security_suite_settings[csp_report_only]" value="0" />';
    echo '<label for="sm-csp-report-only">';
    echo '<input id="sm-csp-report-only" type="checkbox" name="sm_security_suite_settings[csp_report_only]" value="1" ' . checked( 1, $value, false ) . ' /> ';
    echo esc_html__( 'Nur melden, nicht erzwingen (empfohlen waehrend Einfuehrung)', 'sm-security-suite' );
    echo '</label>';
}

/**
 * Rendert Feld fuer HSTS max-age.
 */
function sm_security_suite_render_hsts_max_age_field(): void {
    $value = (int) sm_security_suite_get_setting( 'hsts_max_age' );

    echo '<input type="number" min="0" step="1" name="sm_security_suite_settings[hsts_max_age]" value="' . esc_attr( (string) $value ) . '" class="small-text" />';
    echo '<p class="description">' . esc_html__( '0 deaktiviert HSTS.', 'sm-security-suite' ) . '</p>';
}

/**
 * Rendert Feld fuer Permissions-Policy.
 */
function sm_security_suite_render_permissions_policy_field(): void {
    $value = (string) sm_security_suite_get_setting( 'permissions_policy' );

    echo '<input type="text" name="sm_security_suite_settings[permissions_policy]" value="' . esc_attr( $value ) . '" class="large-text" />';
}

/**
 * Rendert die komplette Einstellungsseite.
 */
function sm_security_suite_render_settings_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    echo '<div class="wrap">';
    echo '<h1>' . esc_html__( 'SM Security Suite', 'sm-security-suite' ) . '</h1>';
    echo '<form action="options.php" method="post">';

    settings_fields( 'sm_security_suite_settings_group' );
    do_settings_sections( 'sm-security-suite' );
    submit_button();

    echo '</form>';
    echo '</div>';
}
