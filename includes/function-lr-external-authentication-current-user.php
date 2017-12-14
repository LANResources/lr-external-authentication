<?php
/**
 * LR External Authentication current_user helper function
 */
namespace LR_External_Authentication;

defined( 'ABSPATH' ) or exit;

/**
 * Helper function to retrieve attributes on the currently authenticated external user.
 *
 * @param string $attr Name of attribute to retrieve
 */
function current_user( $attr ) {
  global $current_external_user;
  if ( $current_external_user != null && array_key_exists( $attr, $current_external_user ) ) {
    return $current_external_user[$attr];
  } else {
    return null;
  }
}
