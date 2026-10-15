=== CODShield for WooCommerce ===
Contributors: codshield
Tags: cash on delivery, cod, fraud, pakistan, uae
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later

Check cash-on-delivery customers against the CODShield network before you ship, and report what happened afterwards.

== Description ==

For stores selling in Pakistan and the UAE.

* Every new cash-on-delivery order is checked. The order gets a risk score (0-100), a band (low, medium, high) and a note for your team.
* Choose what happens to medium and high risk orders: flag only, put on hold for a confirmation call, or hide cash on delivery at checkout so the customer prepays.
* Report outcomes from the order screen: Order actions → "CODShield: report …" (refused at the door, fake order, return abuse and more).
* Completed cash-on-delivery orders are reported as delivered and paid, which lowers that customer's score.
* A "COD risk" column in the orders list.

If CODShield can't be reached, orders go through unchanged.

== Installation ==

1. In CODShield, open Developers and create a live API key with the check and report scopes.
2. In WordPress: Plugins → Add New → Upload Plugin, choose codshield-woocommerce.zip, then Activate.
3. WooCommerce → Settings → CODShield: paste the API key and choose the actions for medium and high risk.

To try it without affecting real data, use a test key (cs_test_...). Sandbox numbers: +923000000001 (high), +923000000002 (medium), +923000000003 (low).

== Frequently Asked Questions ==

= Does hiding cash on delivery work with the block checkout? =
The payment method is hidden when the checkout loads. If the customer changes their phone number afterwards, the block checkout may still show cash on delivery; the order is then checked and handled by the "put on hold" path. The classic checkout refreshes the methods when the phone changes.

= What data is sent? =
Phone, email, delivery address and city of cash-on-delivery orders, to score the customer and to report outcomes. CODShield stores only scrambled fingerprints, never the raw details.

== Changelog ==

= 1.0.0 =
* First release.
