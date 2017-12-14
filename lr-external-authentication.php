<?php
/**
 * Plugin Name:  LR External Authentication
 * Plugin URI:   https://github.com/LANResources/lr-external-authentication/
 * Description:  Walls off a Wordpress Site so that only users authenticated with an external site may access it.
 *
 * Version:      1.0.0
 *
 * Author:       Nick Reed
 * Author URI:   https://github.com/reed/
 *
 * License:      GPL-2.0+
 * License URI:  http://www.gnu.org/licenses/gpl-2.0.txt
 */

defined( 'ABSPATH' ) or exit;

/**
 * Load PHP-JWT
 */
require_once dirname( __FILE__ ) . '/vendor/php-jwt/php-jwt.php';

/**
 * Load the main class of this plugin
 */
require_once dirname( __FILE__ ) . '/includes/class-lr-external-authentication.php';
return new \LR_External_Authentication\Plugin();
