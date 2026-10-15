<?php
// Remove the plugin's settings when it is deleted from WordPress. Order notes and scores stay on orders.
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

foreach ( array( 'api_key', 'api_url', 'gateways', 'high_action', 'medium_action', 'auto_delivered' ) as $key ) {
	delete_option( 'codshield_' . $key );
}
