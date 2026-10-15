<?php
// Run: php plugins/woocommerce/tests/harness.php plugins/woocommerce/codshield/codshield.php <cs_test_ key> <server url>
// Minimal WordPress/WooCommerce stand-ins, enough to run the plugin's logic against a real CODShield server.
define('ABSPATH', __DIR__); define('MINUTE_IN_SECONDS', 60);
$GLOBALS['hooks'] = []; $GLOBALS['opts'] = []; $GLOBALS['transients'] = []; $GLOBALS['is_checkout'] = false; $GLOBALS['customer'] = null;
function add_action($h, $cb, $p = 10, $n = 1) { $GLOBALS['hooks'][$h][] = $cb; }
function add_filter($h, $cb, $p = 10, $n = 1) { $GLOBALS['hooks'][$h][] = $cb; }
function do_action($h, ...$a) { foreach ($GLOBALS['hooks'][$h] ?? [] as $cb) call_user_func_array($cb, $a); }
function apply_filters($h, $v, ...$a) { foreach ($GLOBALS['hooks'][$h] ?? [] as $cb) $v = call_user_func_array($cb, array_merge([$v], $a)); return $v; }
function get_option($k, $d = false) { return $GLOBALS['opts'][$k] ?? $d; }
function __($s) { return $s; } function esc_html__($s) { return $s; } function esc_html($s) { return $s; } function esc_attr($s) { return $s; }
function esc_url($s) { return $s; } function admin_url($s) { return $s; } function plugin_basename($f) { return basename($f); } function wp_kses_post($s) { return $s; }
function wp_json_encode($v) { return json_encode($v); } function untrailingslashit($s) { return rtrim($s, '/'); }
function get_transient($k) { return $GLOBALS['transients'][$k] ?? false; } function set_transient($k, $v, $t) { $GLOBALS['transients'][$k] = $v; }
function delete_transient($k) { unset($GLOBALS['transients'][$k]); }
function is_admin() { return false; } function wp_doing_ajax() { return false; } function is_checkout() { return $GLOBALS['is_checkout']; }
function wc_get_logger() { return new class { function warning($m, $c) { echo "  [log] $m\n"; } }; }
class WP_Error { private $m; function __construct($c, $m) { $this->m = $m; } function get_error_message() { return $this->m; } }
function is_wp_error($x) { return $x instanceof WP_Error; }
function wp_remote_request($url, $args) {
  $ch = curl_init($url); curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $args['method'], CURLOPT_TIMEOUT => $args['timeout'],
    CURLOPT_HTTPHEADER => array_map(fn($k, $v) => "$k: $v", array_keys($args['headers']), $args['headers'])]);
  if (isset($args['body'])) curl_setopt($ch, CURLOPT_POSTFIELDS, $args['body']);
  $body = curl_exec($ch); if ($body === false) return new WP_Error('http', curl_error($ch));
  return ['code' => curl_getinfo($ch, CURLINFO_HTTP_CODE), 'body' => $body];
}
function wp_remote_retrieve_response_code($r) { return $r['code']; } function wp_remote_retrieve_body($r) { return $r['body']; }
class WooCommerce {}
class FakeCustomer { function __construct(public $phone, public $country) {}
  function get_billing_phone() { return $this->phone; } function get_billing_email() { return ''; }
  function get_shipping_country() { return $this->country; } function get_billing_country() { return $this->country; } }
function WC() { return (object)['customer' => $GLOBALS['customer']]; }
class WC_Order {
  public $meta = [], $notes = [], $status = 'processing';
  function __construct(public $num, public $phone, public $method = 'cod', public $country = 'PK') {}
  function get_order_number() { return $this->num; } function get_payment_method() { return $this->method; }
  function get_billing_phone() { return $this->phone; } function get_shipping_phone() { return ''; } function get_billing_email() { return ''; }
  function get_shipping_country() { return $this->country; } function get_billing_country() { return $this->country; }
  function get_shipping_address_1() { return 'House 9'; } function get_shipping_address_2() { return 'Street 4'; }
  function get_billing_address_1() { return ''; } function get_billing_address_2() { return ''; }
  function get_shipping_city() { return 'Lahore'; } function get_billing_city() { return 'Lahore'; }
  function get_total() { return '4500.00'; } function get_currency() { return 'PKR'; }
  function get_meta($k) { return $this->meta[$k] ?? ''; } function update_meta_data($k, $v) { $this->meta[$k] = $v; }
  function add_order_note($n) { $this->notes[] = $n; } function has_status($s) { return in_array($this->status, (array)$s, true); }
  function update_status($s, $n = '') { $this->status = $s; if ($n) $this->notes[] = $n; } function save() {}
}
function wc_get_order($o) { return $o; }

require $argv[1];
$GLOBALS['opts'] = ['codshield_api_key' => $argv[2], 'codshield_api_url' => $argv[3], 'codshield_high_action' => 'hidecod',
                    'codshield_medium_action' => 'hold', 'codshield_auto_delivered' => 'yes'];
do_action('plugins_loaded');
$ok = 0; $fail = 0;
function expect($cond, $what) { global $ok, $fail; echo ($cond ? "  PASS " : "  FAIL ") . "$what\n"; $cond ? $ok++ : $fail++; }

echo "checkout, high risk number (sandbox +923000000001):\n";
$GLOBALS['is_checkout'] = true; $GLOBALS['customer'] = new FakeCustomer('+923000000001', 'PK');
$g = apply_filters('woocommerce_available_payment_gateways', ['cod' => 1, 'stripe' => 1]);
expect(!isset($g['cod']) && isset($g['stripe']), 'cash on delivery hidden, card still offered');
$GLOBALS['customer'] = new FakeCustomer('+923000000003', 'PK');
$g = apply_filters('woocommerce_available_payment_gateways', ['cod' => 1, 'stripe' => 1]);
expect(isset($g['cod']), 'low risk keeps cash on delivery');
$GLOBALS['customer'] = new FakeCustomer('+447700900123', 'GB');
$g = apply_filters('woocommerce_available_payment_gateways', ['cod' => 1]);
expect(isset($g['cod']), 'other countries are not checked');
$errs = new class { public $e = []; function add($c, $m) { $this->e[] = $m; } };
do_action('woocommerce_after_checkout_validation', ['payment_method' => 'cod', 'billing_country' => 'PK', 'billing_phone' => '+923000000001'], $errs);
expect(count($errs->e) === 1, 'placing a COD order for a high-risk number is refused at validation');
$GLOBALS['is_checkout'] = false;

echo "new orders:\n";
$o = new WC_Order('1001', '+923000000002');
do_action('woocommerce_checkout_order_processed', $o);
expect($o->meta['_codshield_band'] === 'medium' && $o->meta['_codshield_score'] === 44, 'medium order scored 44');
expect($o->status === 'on-hold', 'medium order put on hold (setting: hold)');
expect(str_contains(implode(' | ', $o->notes), 'CODShield: medium risk (44/100)'), 'note added for staff');
$p = new WC_Order('1002', '+923000000001', 'stripe');
do_action('woocommerce_checkout_order_processed', $p);
expect(!isset($p->meta['_codshield_band']), 'prepaid order not checked');

echo "outcomes:\n";
do_action('woocommerce_order_action_codshield_refused_at_door', $o);
expect(str_contains(end($o->notes), 'Refused at the door'), 'manual report: ' . end($o->notes));
do_action('woocommerce_order_status_completed', '1003', new WC_Order('1003', '+923000000003'));
$c = new WC_Order('1004', '+923000000003'); do_action('woocommerce_order_status_completed', '1004', $c);
expect(str_contains(end($c->notes), 'Delivered and paid'), 'completed COD order reported as delivered: ' . end($c->notes));
$x = new WC_Order('1005', '12345'); do_action('woocommerce_order_action_codshield_fake_order', $x);
expect(str_contains(end($x->notes), 'could not report'), 'bad phone shows the API error: ' . end($x->notes));

echo "server down:\n";
$GLOBALS['opts']['codshield_api_url'] = 'http://127.0.0.1:9'; $GLOBALS['transients'] = [];
$d = new WC_Order('1006', '+923000000001'); do_action('woocommerce_checkout_order_processed', $d);
expect($d->status === 'processing' && str_contains(end($d->notes), 'could not be completed'), 'fails open: order unchanged');
echo "\n$ok passed, $fail failed\n";
exit($fail ? 1 : 0);
