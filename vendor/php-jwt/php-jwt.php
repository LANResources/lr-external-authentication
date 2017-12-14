<?php
/**
 * Plugin Name:  firebase/php-jwt
 * Plugin URI:   https://github.com/firebase/php-jwt
 * Description:  A simple library to encode and decode JSON Web Tokens (JWT) in PHP. Should conform to the current spec.
 *
 * Version:      5.0.0
 *
 * Author:       Neuman Vong, Anant Narayanan
 *
 * License:      BSD-3-Clause
 */

defined( 'ABSPATH' ) or exit;
require_once dirname( __FILE__ ) . '/src/BeforeValidException.php';
require_once dirname( __FILE__ ) . '/src/ExpiredException.php';
require_once dirname( __FILE__ ) . '/src/SignatureInvalidException.php';
require_once dirname( __FILE__ ) . '/src/JWT.php';
