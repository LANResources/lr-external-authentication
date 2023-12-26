<?php
/**
 * LR External Authentication Plugin Core Class
 */
namespace LR_External_Authentication;

defined( 'ABSPATH' ) or exit;

require_once dirname( __FILE__ ) . '/function-lr-external-authentication-current-user.php';

/**
 * LR External Authentication main class.
 */
class Plugin {
  /**
   * The plugin version.
   *
   * @const string
   */
  CONST VERSION = '1.1.0';

  /**
   * The plugin name.
   *
   * @const string
   */
  CONST NAME = 'LR External Authentication';

  /**
   * This plugin's settings options.
   *
   * @access protected
   * @var    array $options Array of this plugin settings options.
   */
  protected $options = array();

  /**
   * Load plugin.
   */
  public function __construct() {
    // Set options.
    $this->options = $this->get_options();

    // Load admin.
    $this->set_admin();

    // Bail out if JWT can't be found.
    if ( ! class_exists( 'Firebase\JWT' ) ) {
      return;
    }

    // Bail out if the plugin's options are invalid
    if ( count( $this->verify_options() ) > 0 ) {
      return;
    }

    // LR External Authentication initialization
    add_action( 'template_redirect', array( $this, 'init' ) );
  }


  /**
   * Load admin.
   */
  private function set_admin() {
    if ( ! defined( 'DOING_AJAX' ) && is_admin() ) {
      // Add a settings link to the plugins admin screen.
      $plugin_name = str_replace( 'includes/class-', '', plugin_basename( __FILE__ ) );
      add_filter( "plugin_action_links_{$plugin_name}", function( $actions ) {
        return array_merge( array(
          '<a href="' . esc_url( admin_url( 'options-general.php?page=lr-external-authentication' ) ) . '">Settings</a>',
        ), $actions );
      } );

      // Init settings.
      require_once __DIR__ . '/class-lr-external-authentication-settings.php';
      new Settings( $this->options );
    }
  }


  /**
   * Get LR External Authentication settings options.
   *
   * @return array of plugin options
   */
  protected function get_options() {
    $options = get_option( 'lr_external_authentication', array() );

    return wp_parse_args( $options, array(
      'ext_site'                 => '',
      'ext_site_redirector_path' => '',
      'ext_site_session_path'    => '',
      'ext_site_secret_key'      => '',
      'ext_site_token_iss'       => '',
      'cookie_prefix'            => '_lr_ext_auth_',
      'session_expire'           => 0,
      'use_ssl'                  => false
    ) );
  }


  /**
   * Initialize LR External Authentication
   */
  public function init() {

    if ( $this->is_authenticated() ) { // Check if user session cookie exists

      // Read session cookie and set user information
      $this->initialize_current_external_user();

    } elseif ( $this->auth_token_present() ) { // Check if an authorization token has been passed through a GET variable

      // Decode and validate the passed auth token.  
      // If valid, redirect to initially requested page.  
      // If not, redirect to external site login
      $this->verify_auth_token();

    } else {

      // Redirect to external site login
      $this->external_login_redirect();
    
    }
  }

  /**
   * Verifies that all of the plugin's options are valid
   *
   * @return array the names of the invalid options
   */
  private function verify_options() {
    $invalid_options = array();

    // Verifies that the ext_site option isn't empty or contain any spaces
    if ( ! preg_match( '/^\S+$/', $this->options['ext_site'] ) ) {
      array_push( $invalid_options, 'ext_site' );
    }

    // Verifies that the ext_site_redirector_path option isn't empty or contain any spaces and begins with a forward slash (/)
    if ( ! preg_match( '/^\/\S+$/', $this->options['ext_site_redirector_path'] ) ) {
      array_push( $invalid_options, 'ext_site_redirector_path' );
    }

    // Verifies that the ext_site_session_path option isn't empty or contain any spaces and begins with a forward slash (/)
    if ( ! preg_match( '/^\/\S+$/', $this->options['ext_site_session_path'] ) ) {
      array_push( $invalid_options, 'ext_site_session_path' );
    }

    // Verifies that the ext_site_secret_key option isn't empty or contain any spaces
    if ( ! preg_match( '/^\S+$/', $this->options['ext_site_secret_key'] ) ) {
      array_push( $invalid_options, 'ext_site_secret_key' );
    }

    // Verifies that the ext_site_token_iss option isn't empty or contain any spaces
    if ( ! preg_match( '/^\S+$/', $this->options['ext_site_token_iss'] ) ) {
      array_push( $invalid_options, 'ext_site_token_iss' );
    }

    return $invalid_options;
  }

  /**
   * Checks if the session cookie is present
   *
   * @return boolean
   */
  private function is_authenticated() {
    return array_key_exists( $this->cookie_name( 'session' ), $_COOKIE );
  }

  /**
   * Reads the session cookie and saves the current user data in a variable to be accessed by get_current_user()
   */
  private function initialize_current_external_user() {
    global $current_external_user;
    $current_external_user = json_decode( stripslashes( $_COOKIE[$this->cookie_name( 'session' )] ), true );
  }

  /**
   * Checks if a token was passed through a GET variable
   *
   * @return boolean
   */
  private function auth_token_present() {
    return array_key_exists( 'token', $_GET );
  }

  /**
   * Decodes verifies the authenticity of the authorization token passed in through a GET variable.
   * If it's valid, the user is signed in and redirected to the initially requested page.
   * If it's not valid, or if any part of the process fails, the user is redirected back to the external site for reauthentication.
   */
  private function verify_auth_token() {
    try {
      $token = $_GET['token'];
      $decoded_token = $this->decode_token( $token );

      if ( array_key_exists( 'iss', $decoded_token ) && $decoded_token['iss'] == $this->options['ext_site_token_iss'] ) {
        $external_session_data = $this->get_session_from_token( $token );

        if ( true === $external_session_data['logged_in'] ) {
          $this->sign_in_user( $external_session_data );

          if ( array_key_exists( $this->cookie_name( 'session_return_url' ), $_COOKIE ) ) {
            $this->session_return_url( 'delete' );
            $this->redirect_to( $_COOKIE[$this->cookie_name( 'session_return_url' )] );
          } else {
            $this->redirect_to( $decoded_token['return_url'] );
          }
        } else {
          throw new Exception();
        }
      } else {
        throw new Exception();
      }
    } catch ( Exception $e ) {
      $this->external_login_redirect();
    }
  }

  /**
   * Saves the user data received from the external site in a session cookie.  
   * The existence of this cookie means the user is signed in.
   * 
   * @param array $session_data an associative array containing the user's session data
   */
  private function sign_in_user( $session_data ) {
    $this->set_cookie( 'session', json_encode($session_data), ( 0 == $this->options['session_expire'] ) ? 0 : time() + $this->options['session_expire'] );
  }

  /**
   * Sends the authorization token back to the external site to verify that the user is signed in.  
   * This extra step prevents someone from using the same token indefinitely.
   * The external site will pass back a JSON string containing information about the user.
   * If the request does not return a status code of 200, the user is redirected back to the external site for reauthentication.
   *
   * @param string $token the JWT authorization token passed in through a GET variable
   */
  private function get_session_from_token( $token ) {
    $response = wp_remote_get( $this->external_site_url( $this->options['ext_site_session_path'] ) . "?basic=true&token=" . $token );
    if ( 200 == wp_remote_retrieve_response_code( $response ) ) {
      return json_decode( wp_remote_retrieve_body( $response ), true );
    } else {
      $this->external_login_redirect();
    }
  }

  /**
   * Builds a URI to the external authentication site
   *
   * @param string $path the optional pathname to append to the URI
   * @return string the complete URI
   */
  private function external_site_url( $path = '' ) {
    return ( ( true === $this->options['use_ssl'] ) ? 'https://' : 'http://' ) . $this->options['ext_site'] . $path;
  }

  /**
   * Saves the current page URL in a cookie and redirects the user to the external site for authentication
   */
  private function external_login_redirect() {
    $this->session_return_url( 'set' );
    $this->redirect_to( $this->external_site_url( $this->options['ext_site_redirector_path'] ) . "?redirect=" . $this->current_page() );
  }

  /**
   * Sets or deletes the cookie containing the current page's URL.  
   * Used to redirect the user back to the desired page after authenticating.
   *
   * @param string $action accepts either 'set' or 'delete', indicating which action to take
   */
  private function session_return_url( $action ) {
    switch ( $action ) {
      case 'set':
        $this->set_cookie( 'session_return_url', $this->current_page(), time()+120 );
        break;
      case 'delete':
        $this->set_cookie( 'session_return_url', null, 0 );
        break;
    }
  }

  /**
   *
   * Utility Functions
   *
   */

  /**
   * Redirects the site to a given URL and then kills the script
   *
   * @param string $url the URL to redirect to
   */
  private function redirect_to( $url ) {
    header( "Location: " . $url );
    die();
  }

  /**
   * Decodes a JSON Web Token (JWT)
   *
   * @param string $token the JSON web token to decode
   * @return array the decoded data
   */
  private function decode_token( $token ) {
    return (array) \Firebase\JWT::decode( $token, $this->options['ext_site_secret_key'], array('HS256') );
  }

  /**
   * Sets a cookie with the default options
   *
   * @param string $key the name of the cookie
   * @param string $value the data to save in the cookie
   * @param mixed $expire the expiration time for the cookie
   */
  private function set_cookie( $key, $value, $expire ) {
    setcookie( $this->cookie_name($key), $value, $expire, COOKIEPATH, COOKIE_DOMAIN, false, true );
  }

  /**
   * Appends the default cookie prefix to the given key name
   * 
   * @param string $key optional key name to append to the cookie prefix
   */
  private function cookie_name( $key = '' ) {
    return $this->options['cookie_prefix'] . $key;
  }

  /**
   * Returns the URI of the current page
   */
  private function current_page() {
    $protocol = ( strpos( get_option( 'siteurl' ), 'https://' ) === 0 ) ? 'https://' : 'http://';
    return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
  }
}
