<?php
/**
 * Plugin Name:       CODShield for WooCommerce
 * Plugin URI:        https://codshield-sx1i.onrender.com/developers
 * Description:       Checks cash-on-delivery customers against the CODShield network (Pakistan and UAE), can hide cash on delivery or hold risky orders, and reports delivery outcomes.
 * Version:           1.0.0
 * Author:            CODShield
 * License:           GPL-2.0-or-later
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * WC requires at least: 7.0
 * WC tested up to:   10.2
 * Text Domain:       codshield
 */

defined( 'ABSPATH' ) || exit;

final class CODShield_WC {

	const VERSION = '1.0.0';
	const OPT     = 'codshield_';
	const OUTCOMES = array(
		'refused_at_door' => 'Refused at the door',
		'unreachable'     => 'Phone off / unreachable on delivery',
		'fake_order'      => 'Customer says they never ordered',
		'fake_address'    => 'Address does not exist',
		'return_abuse'    => 'Returned used, swapped or damaged',
		'chargeback'      => 'Prepaid order charged back',
		'delivered_paid'  => 'Delivered and paid',
	);

	public static function init() {
		add_action( 'before_woocommerce_init', array( __CLASS__, 'declare_compat' ) );
		add_action( 'plugins_loaded', array( __CLASS__, 'boot' ) );
	}

	public static function declare_compat() {
		if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__, true );
		}
	}

	public static function boot() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			add_action( 'admin_notices', function () {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'CODShield needs WooCommerce to be active.', 'codshield' ) . '</p></div>';
			} );
			return;
		}
		// settings
		add_filter( 'woocommerce_settings_tabs_array', array( __CLASS__, 'settings_tab' ), 60 );
		add_action( 'woocommerce_settings_tabs_codshield', array( __CLASS__, 'settings_show' ) );
		add_action( 'woocommerce_update_options_codshield', array( __CLASS__, 'settings_save' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( __CLASS__, 'action_links' ) );

		// checkout
		add_filter( 'woocommerce_available_payment_gateways', array( __CLASS__, 'filter_gateways' ) );
		add_action( 'woocommerce_after_checkout_validation', array( __CLASS__, 'validate_checkout' ), 10, 2 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'checkout_script' ) );

		// new orders (classic checkout and block checkout)
		add_action( 'woocommerce_checkout_order_processed', array( __CLASS__, 'on_new_order' ), 20, 1 );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( __CLASS__, 'on_new_order' ), 20, 1 );

		// outcomes
		add_filter( 'woocommerce_order_actions', array( __CLASS__, 'order_actions' ), 10, 2 );
		foreach ( array_keys( self::OUTCOMES ) as $type ) {
			add_action( 'woocommerce_order_action_codshield_' . $type, function ( $order ) use ( $type ) {
				self::report( $order, $type, true );
			} );
		}
		add_action( 'woocommerce_order_action_codshield_recheck', function ( $order ) {
			self::check_order( $order, true );
		} );
		add_action( 'woocommerce_order_status_completed', array( __CLASS__, 'on_completed' ), 10, 2 );

		// admin display
		add_action( 'add_meta_boxes', array( __CLASS__, 'meta_box' ) );
		add_filter( 'manage_edit-shop_order_columns', array( __CLASS__, 'column' ) );
		add_action( 'manage_shop_order_posts_custom_column', array( __CLASS__, 'column_legacy' ), 10, 2 );
		add_filter( 'manage_woocommerce_page_wc-orders_columns', array( __CLASS__, 'column' ) );
		add_action( 'manage_woocommerce_page_wc-orders_custom_column', array( __CLASS__, 'column_hpos' ), 10, 2 );
	}

	/* ------------------------------------------------------------ settings */

	public static function opt( $key, $default = '' ) {
		$v = get_option( self::OPT . $key, $default );
		return ( '' === $v || null === $v ) ? $default : $v;
	}

	public static function settings_tab( $tabs ) {
		$tabs['codshield'] = __( 'CODShield', 'codshield' );
		return $tabs;
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=wc-settings&tab=codshield' ) ) . '">' . esc_html__( 'Settings', 'codshield' ) . '</a>' );
		return $links;
	}

	public static function fields() {
		$actions = array(
			'flag'    => __( 'Flag it only (score and note on the order)', 'codshield' ),
			'hold'    => __( 'Put the order on hold for a confirmation call', 'codshield' ),
			'hidecod' => __( 'Hide cash on delivery at checkout (customer must prepay)', 'codshield' ),
		);
		return array(
			array( 'title' => __( 'CODShield', 'codshield' ), 'type' => 'title', 'id' => 'codshield_section',
				'desc' => __( 'Create a live API key with the <b>check</b> and <b>report</b> scopes in CODShield (Developers tab) and paste it below. Only orders from Pakistan and the UAE are checked.', 'codshield' ) ),
			array( 'title' => __( 'API key', 'codshield' ), 'id' => self::OPT . 'api_key', 'type' => 'password', 'default' => '',
				'desc_tip' => __( 'Starts with cs_live_ (or cs_test_ for sandbox testing).', 'codshield' ) ),
			array( 'title' => __( 'Server address', 'codshield' ), 'id' => self::OPT . 'api_url', 'type' => 'text',
				'default' => 'https://codshield-sx1i.onrender.com' ),
			array( 'title' => __( 'Cash on delivery methods', 'codshield' ), 'id' => self::OPT . 'gateways', 'type' => 'text', 'default' => 'cod',
				'desc_tip' => __( 'Payment method IDs treated as cash on delivery, separated by commas. WooCommerce\'s own is "cod".', 'codshield' ) ),
			array( 'title' => __( 'High risk orders', 'codshield' ), 'id' => self::OPT . 'high_action', 'type' => 'select', 'default' => 'hold', 'options' => $actions ),
			array( 'title' => __( 'Medium risk orders', 'codshield' ), 'id' => self::OPT . 'medium_action', 'type' => 'select', 'default' => 'flag', 'options' => $actions ),
			array( 'title' => __( 'Report delivered orders', 'codshield' ), 'id' => self::OPT . 'auto_delivered', 'type' => 'checkbox', 'default' => 'yes',
				'desc' => __( 'When a cash-on-delivery order is marked Completed, tell CODShield it was delivered and paid (this lowers that customer\'s risk).', 'codshield' ) ),
			array( 'type' => 'sectionend', 'id' => 'codshield_section' ),
		);
	}

	public static function settings_show() {
		woocommerce_admin_fields( self::fields() );
		$key = self::opt( 'api_key' );
		if ( $key ) {
			$r = self::request( 'GET', '/v1/me', null, 6 );
			if ( is_wp_error( $r ) ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( __( 'Could not reach CODShield: %s', 'codshield' ), $r->get_error_message() ) ) . '</p></div>';
			} else {
				$t = isset( $r['tenant']['name'] ) ? $r['tenant']['name'] : '';
				echo '<div class="notice notice-success inline"><p>' . esc_html( sprintf( __( 'Connected to CODShield as %s.', 'codshield' ), $t ) ) . '</p></div>';
			}
		}
		echo '<p class="description">' . wp_kses_post( __( 'Report what happened to an order from the order screen: <b>Order actions → CODShield: …</b>', 'codshield' ) ) . '</p>';
	}

	public static function settings_save() {
		woocommerce_update_options( self::fields() );
	}

	/* ------------------------------------------------------------ API */

	public static function request( $method, $path, $body = null, $timeout = 8 ) {
		$key = trim( (string) self::opt( 'api_key' ) );
		if ( '' === $key ) {
			return new WP_Error( 'codshield_no_key', __( 'No CODShield API key set.', 'codshield' ) );
		}
		$args = array(
			'method'  => $method,
			'timeout' => $timeout,
			'headers' => array( 'X-API-Key' => $key, 'Content-Type' => 'application/json', 'User-Agent' => 'CODShield-WooCommerce/' . self::VERSION ),
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}
		$res = wp_remote_request( untrailingslashit( self::opt( 'api_url', 'https://codshield-sx1i.onrender.com' ) ) . $path, $args );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( $code < 200 || $code >= 300 ) {
			$msg = isset( $data['error']['message'] ) ? $data['error']['message'] : ( is_string( $data['detail'] ?? null ) ? $data['detail'] : 'HTTP ' . $code );
			return new WP_Error( 'codshield_http_' . $code, $msg );
		}
		return is_array( $data ) ? $data : array();
	}

	private static function log( $msg ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->warning( $msg, array( 'source' => 'codshield' ) );
		}
	}

	/** Customer details from an order, or null when the order isn't from Pakistan or the UAE. */
	public static function customer_of( $order ) {
		$country = strtoupper( $order->get_shipping_country() ? $order->get_shipping_country() : $order->get_billing_country() );
		if ( ! in_array( $country, array( 'PK', 'AE' ), true ) ) {
			return null;
		}
		$phone = $order->get_billing_phone();
		if ( ! $phone && method_exists( $order, 'get_shipping_phone' ) ) {
			$phone = $order->get_shipping_phone();
		}
		$address = trim( $order->get_shipping_address_1() . ' ' . $order->get_shipping_address_2() );
		if ( '' === $address ) {
			$address = trim( $order->get_billing_address_1() . ' ' . $order->get_billing_address_2() );
		}
		$city = $order->get_shipping_city() ? $order->get_shipping_city() : $order->get_billing_city();
		return array_filter( array(
			'phone'   => $phone,
			'email'   => $order->get_billing_email(),
			'address' => $address,
			'city'    => $city,
			'country' => $country,
		) );
	}

	/** Score a customer. Cached for 30 minutes so checkout refreshes don't call the API repeatedly. */
	public static function check( $who ) {
		if ( empty( $who['phone'] ) && empty( $who['email'] ) ) {
			return null;
		}
		$cache = 'codshield_' . md5( wp_json_encode( $who ) );
		$hit   = get_transient( $cache );
		if ( is_array( $hit ) ) {
			return $hit;
		}
		$r = self::request( 'POST', '/v1/check', $who );
		if ( is_wp_error( $r ) ) {
			self::log( 'check failed: ' . $r->get_error_message() );
			return null;                       // fail open: never block an order because the check failed
		}
		set_transient( $cache, $r, 30 * MINUTE_IN_SECONDS );
		return $r;
	}

	public static function is_cod( $method_id ) {
		$ids = array_filter( array_map( 'trim', explode( ',', (string) self::opt( 'gateways', 'cod' ) ) ) );
		return in_array( $method_id, $ids, true );
	}

	private static function action_for( $band ) {
		if ( 'high' === $band ) {
			return self::opt( 'high_action', 'hold' );
		}
		if ( 'medium' === $band ) {
			return self::opt( 'medium_action', 'flag' );
		}
		return 'flag';
	}

	/* ------------------------------------------------------------ checkout */

	private static function checkout_customer() {
		if ( ! function_exists( 'WC' ) || ! WC()->customer ) {
			return null;
		}
		$c       = WC()->customer;
		$country = strtoupper( $c->get_shipping_country() ? $c->get_shipping_country() : $c->get_billing_country() );
		if ( ! in_array( $country, array( 'PK', 'AE' ), true ) || ! $c->get_billing_phone() ) {
			return null;
		}
		return array_filter( array(
			'phone'   => $c->get_billing_phone(),
			'email'   => $c->get_billing_email(),
			'country' => $country,
		) );
	}

	public static function filter_gateways( $gateways ) {
		if ( is_admin() && ! wp_doing_ajax() ) {
			return $gateways;
		}
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout() ) {
			return $gateways;
		}
		$who = self::checkout_customer();
		if ( ! $who ) {
			return $gateways;
		}
		$r = self::check( $who );
		if ( $r && isset( $r['band'] ) && 'hidecod' === self::action_for( $r['band'] ) ) {
			foreach ( array_keys( $gateways ) as $id ) {
				if ( self::is_cod( $id ) ) {
					unset( $gateways[ $id ] );
				}
			}
		}
		return $gateways;
	}

	public static function validate_checkout( $data, $errors ) {
		if ( empty( $data['payment_method'] ) || ! self::is_cod( $data['payment_method'] ) ) {
			return;
		}
		$country = strtoupper( ! empty( $data['shipping_country'] ) ? $data['shipping_country'] : ( $data['billing_country'] ?? '' ) );
		if ( ! in_array( $country, array( 'PK', 'AE' ), true ) || empty( $data['billing_phone'] ) ) {
			return;
		}
		$r = self::check( array_filter( array( 'phone' => $data['billing_phone'], 'email' => $data['billing_email'] ?? '', 'country' => $country ) ) );
		if ( $r && isset( $r['band'] ) && 'hidecod' === self::action_for( $r['band'] ) ) {
			$errors->add( 'codshield', __( 'Cash on delivery isn\'t available for this order. Please choose another payment method.', 'codshield' ) );
		}
	}

	public static function checkout_script() {
		if ( function_exists( 'is_checkout' ) && is_checkout() && wp_script_is( 'wc-checkout', 'enqueued' ) ) {
			// refresh payment methods when the phone number changes, so the check sees it
			wp_add_inline_script( 'wc-checkout', 'jQuery(function($){$("form.checkout").on("change","#billing_phone",function(){$(document.body).trigger("update_checkout");});});' );
		}
	}

	/* ------------------------------------------------------------ orders */

	public static function on_new_order( $order ) {
		$order = is_numeric( $order ) ? wc_get_order( $order ) : $order;
		if ( ! $order || ! self::is_cod( $order->get_payment_method() ) || $order->get_meta( '_codshield_band' ) ) {
			return;
		}
		self::check_order( $order, false );
	}

	public static function check_order( $order, $manual ) {
		$who = self::customer_of( $order );
		if ( ! $who ) {
			if ( $manual ) {
				$order->add_order_note( __( 'CODShield: only orders from Pakistan or the UAE can be checked.', 'codshield' ) );
			}
			return;
		}
		if ( $manual ) {
			delete_transient( 'codshield_' . md5( wp_json_encode( $who ) ) );
		}
		$r = self::check( $who );
		if ( ! $r || ! isset( $r['band'] ) ) {
			$order->add_order_note( __( 'CODShield: the check could not be completed. The order was not changed.', 'codshield' ) );
			return;
		}
		$order->update_meta_data( '_codshield_band', $r['band'] );
		$order->update_meta_data( '_codshield_score', (int) $r['score'] );
		$order->update_meta_data( '_codshield_reasons', isset( $r['reasons'] ) ? implode( '; ', (array) $r['reasons'] ) : '' );
		$order->update_meta_data( '_codshield_checked_at', gmdate( 'c' ) );
		$advice = array(
			'low'    => __( 'ship normally', 'codshield' ),
			'medium' => __( 'confirm by call or OTP before shipping', 'codshield' ),
			'high'   => __( 'ask for prepayment or a part advance', 'codshield' ),
		);
		/* translators: 1: band, 2: score, 3: advice */
		$note = sprintf( __( 'CODShield: %1$s risk (%2$d/100), %3$s.', 'codshield' ), $r['band'], (int) $r['score'], $advice[ $r['band'] ] ?? '' );
		if ( ! empty( $r['reasons'] ) ) {
			$note .= ' ' . implode( '; ', array_slice( (array) $r['reasons'], 0, 3 ) ) . '.';
		}
		$order->add_order_note( $note );
		if ( ! $manual && in_array( self::action_for( $r['band'] ), array( 'hold', 'hidecod' ), true ) && $order->has_status( array( 'pending', 'processing' ) ) ) {
			$order->update_status( 'on-hold', __( 'CODShield: held for a confirmation call.', 'codshield' ) );
		}
		$order->save();
	}

	public static function order_actions( $actions, $order = null ) {
		$actions['codshield_recheck'] = __( 'CODShield: check this customer again', 'codshield' );
		foreach ( self::OUTCOMES as $type => $label ) {
			/* translators: %s: outcome */
			$actions[ 'codshield_' . $type ] = sprintf( __( 'CODShield: report "%s"', 'codshield' ), $label );
		}
		return $actions;
	}

	public static function on_completed( $order_id, $order = null ) {
		if ( 'yes' !== self::opt( 'auto_delivered', 'yes' ) ) {
			return;
		}
		$order = $order ? $order : wc_get_order( $order_id );
		if ( $order && self::is_cod( $order->get_payment_method() ) ) {
			self::report( $order, 'delivered_paid', false );
		}
	}

	public static function report( $order, $type, $manual ) {
		if ( ! isset( self::OUTCOMES[ $type ] ) ) {
			return;
		}
		$who = self::customer_of( $order );
		if ( ! $who ) {
			if ( $manual ) {
				$order->add_order_note( __( 'CODShield: only orders from Pakistan or the UAE can be reported.', 'codshield' ) );
			}
			return;
		}
		$body = array_merge( $who, array(
			'order_ref'   => 'wc-' . $order->get_order_number(),
			'type'        => $type,
			'occurred_at' => gmdate( 'c' ),
			'amount'      => (float) $order->get_total(),
			'currency'    => $order->get_currency(),
			'evidence'    => 'WooCommerce order #' . $order->get_order_number(),
		) );
		$r = self::request( 'POST', '/v1/events', $body );
		if ( is_wp_error( $r ) ) {
			/* translators: %s: error */
			$order->add_order_note( sprintf( __( 'CODShield: could not report the outcome (%s).', 'codshield' ), $r->get_error_message() ) );
			return;
		}
		$status = isset( $r['outcome'] ) ? $r['outcome'] : 'sent';
		$text   = 'duplicate' === $status ? __( 'already reported', 'codshield' ) : ( 'pending' === $status ? __( 'waiting for approval', 'codshield' ) : __( 'reported', 'codshield' ) );
		/* translators: 1: outcome, 2: status */
		$order->add_order_note( sprintf( __( 'CODShield: "%1$s" %2$s.', 'codshield' ), self::OUTCOMES[ $type ], $text ) );
	}

	/* ------------------------------------------------------------ admin display */

	public static function meta_box() {
		$screen = function_exists( 'wc_get_page_screen_id' ) ? wc_get_page_screen_id( 'shop-order' ) : 'shop_order';
		add_meta_box( 'codshield', __( 'CODShield risk', 'codshield' ), array( __CLASS__, 'meta_box_html' ), $screen, 'side', 'high' );
	}

	public static function meta_box_html( $post_or_order ) {
		$order = ( $post_or_order instanceof WC_Order ) ? $post_or_order : wc_get_order( $post_or_order->ID );
		if ( ! $order ) {
			return;
		}
		$band = $order->get_meta( '_codshield_band' );
		if ( ! $band ) {
			echo '<p>' . esc_html__( 'Not checked. Use Order actions → "CODShield: check this customer again".', 'codshield' ) . '</p>';
			return;
		}
		$colors = array( 'low' => '#1a7f37', 'medium' => '#9a6700', 'high' => '#cf222e' );
		printf( '<p style="font-size:15px;margin:0 0 6px"><b style="color:%s">%s</b> &middot; %d/100</p>',
			esc_attr( $colors[ $band ] ?? '#555' ), esc_html( ucfirst( $band ) . ' ' . __( 'risk', 'codshield' ) ), (int) $order->get_meta( '_codshield_score' ) );
		$reasons = $order->get_meta( '_codshield_reasons' );
		if ( $reasons ) {
			echo '<p style="margin:0 0 6px">' . esc_html( $reasons ) . '</p>';
		}
		echo '<p class="description" style="margin:0">' . esc_html__( 'Report what happened from Order actions.', 'codshield' ) . '</p>';
	}

	public static function column( $cols ) {
		$out = array();
		foreach ( $cols as $k => $v ) {
			$out[ $k ] = $v;
			if ( 'order_status' === $k ) {
				$out['codshield'] = __( 'COD risk', 'codshield' );
			}
		}
		if ( ! isset( $out['codshield'] ) ) {
			$out['codshield'] = __( 'COD risk', 'codshield' );
		}
		return $out;
	}

	private static function column_html( $order ) {
		$band = $order ? $order->get_meta( '_codshield_band' ) : '';
		if ( ! $band ) {
			echo '&ndash;';
			return;
		}
		$colors = array( 'low' => '#1a7f37', 'medium' => '#9a6700', 'high' => '#cf222e' );
		printf( '<span style="color:%s;font-weight:600">%s</span> %d', esc_attr( $colors[ $band ] ?? '#555' ), esc_html( ucfirst( $band ) ), (int) $order->get_meta( '_codshield_score' ) );
	}

	public static function column_legacy( $col, $post_id ) {
		if ( 'codshield' === $col ) {
			self::column_html( wc_get_order( $post_id ) );
		}
	}

	public static function column_hpos( $col, $order ) {
		if ( 'codshield' === $col ) {
			self::column_html( $order );
		}
	}
}

CODShield_WC::init();
