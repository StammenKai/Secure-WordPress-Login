<?php
/**
 * Deinstallation fuer SM Security Suite.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Plugin-eigene Optionen entfernen.
delete_option( 'sm_security_suite_version' );
delete_option( 'sm_security_suite_settings' );

// Login-Rate-Limit-Transients (inkl. Timeout-Eintraege) aufraeumen.
global $wpdb;

$transient_prefix = 'sm_login_attempts_';
$option_like      = '_transient_' . $transient_prefix . '%';
$timeout_like     = '_transient_timeout_' . $transient_prefix . '%';

$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
        $option_like,
        $timeout_like
    )
);
