<?php
/**
 * Plugin Name:       SM Security Suite
 * Plugin URI:        https://stammenmedia.de/
 * Description:       Login-Schutz (Rate Limiting + Custom Login URL) und Security Header fuer WordPress.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      8.2
 * Author:            stammenmedia
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sm-security-suite
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'SM_SECURITY_SUITE_VERSION', '1.0.0' );
define( 'SM_SECURITY_SUITE_FILE', __FILE__ );
define( 'SM_SECURITY_SUITE_PATH', plugin_dir_path( __FILE__ ) );
define( 'SM_SECURITY_SUITE_URL', plugin_dir_url( __FILE__ ) );

require_once SM_SECURITY_SUITE_PATH . 'includes/admin-settings.php';
require_once SM_SECURITY_SUITE_PATH . 'includes/login-protection.php';
require_once SM_SECURITY_SUITE_PATH . 'includes/security-headers.php';

/**
 * Laedt Uebersetzungen des Plugins.
 */
function sm_security_suite_load_textdomain(): void {
    load_plugin_textdomain( 'sm-security-suite', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}
add_action( 'plugins_loaded', 'sm_security_suite_load_textdomain' );

/**
 * Aktivierungsroutine des Plugins.
 */
function sm_security_suite_activate(): void {
    update_option( 'sm_security_suite_version', SM_SECURITY_SUITE_VERSION, false );
    add_option( 'sm_security_suite_settings', sm_security_suite_get_default_settings(), '', false );

    if ( function_exists( 'sm_login_add_rewrite' ) ) {
        sm_login_add_rewrite();
    }

    flush_rewrite_rules( false );
}
register_activation_hook( __FILE__, 'sm_security_suite_activate' );

/**
 * Deaktivierungsroutine des Plugins.
 */
function sm_security_suite_deactivate(): void {
    flush_rewrite_rules( false );
}
register_deactivation_hook( __FILE__, 'sm_security_suite_deactivate' );
