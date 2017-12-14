<?php
/**
 * LR External Authentication Plugin Settings Class
 */
namespace LR_External_Authentication;

defined( 'ABSPATH' ) or exit;

/**
 * LR External Authentication Plugin Settings class
 */
class Settings {
  /**
   * This plugin's settings page slug.
   *
   * @access private
   * @var    string
   */
  private $page = '';

  /**
   * This plugin's option name.
   *
   * @access private
   * @var    string
   */
  private $option = '';

  /**
   * This plugin's settings options.
   *
   * @access private
   * @var    array $options Array of this plugin settings options.
   */
  private $options = array();

  /**
   * Register settings and admin menu.
   *
   * @param array $options Plugin settings options.
   */
  public function __construct( array $options ) {
    $this->page    = sanitize_title( strtolower( Plugin::NAME ) );
    $this->option  = str_replace( '-', '_', $this->page );
    $this->options = $options;

    add_action( 'admin_menu', array( $this, 'register_settings_page' ) );
  }

  /**
   * Plugin Settings menu.
   */
  public function register_settings_page() {
    add_options_page(
      __( 'LR External Authentication', 'lr-external-authentication' ),
      __( 'LR External Authentication', 'lr-external-authentication' ),
      'manage_options',
      $this->page,
      array( $this, 'settings_page' )
    );

    add_action( 'admin_init', array( $this, 'register_settings'  ) );
  }

  /**
   * Register plugin settings.
   */
  public function register_settings() {
    register_setting(
      $this->option,
      $this->option,
      array( $this, 'sanitize_field' )
    );

    add_settings_section(
      $this->option,
      __( 'Settings', 'lr-external-authentication' ),
      array( $this, 'settings_info' ),
      $this->page
    );

    $settings_fields = array(
      'External Site Domain' => array( 
        'ext_site', 
        'string', 
        "The domain of the external site.  Exclude the protocol and any trailing slashes.  <b>Ex. example.com</b>", 
        true
      ),
      'External Site Redirector Path' => array(
        'ext_site_redirector_path', 
        'string', 
        "The path on the external site to redirect unauthenticated users to.  The page at that path should authenticate the user and redirect them back to this site.  Include the opening slash.  <b>Ex. /external-auth</b>", 
        true
      ),
      'External Site Session Path' => array(
        'ext_site_session_path', 
        'string', 
        "The path on the external site to query to retrieve information on the authenticated user.  The page at that path should receive a JWT token and return JSON containing the user's information. <b>Ex. /api/session</b>", 
        true
      ),
      'External Site Secret Key' => array(
        'ext_site_secret_key', 
        'string', 
        "The key to use to decrypt JWT session tokens sent by the external site.  Get this from the administrator of the external site.", 
        true
      ),
      'External Site Token Issuer' => array(
        'ext_site_token_iss', 
        'string', 
        "The expected issuer of the external site's token.  As an extra layer of security, after decrypting the token from the external site, the <b>iss</b> key should match the value given here.  Get this from the administrator of the external site.  In most cases, it will be the same as the value of the External Site Domain setting.  <b>Ex. example.com</b>", 
        true
      ),
      'Cookie Prefix' => array(
        'cookie_prefix', 
        'string', 
        "The prefix to use when creating cookies.  Best practice would be to begin and end with an underscore.  <b>Ex. _sitename_ext_auth_</b>", 
        true
      ),
      'Session Duration' => array(
        'session_expire', 
        'number', 
        "The duration (in seconds) that a user's session should last before re-authenticating with the external application.  A value of 0 will cause the session to last until the browser is closed (default).  <b>Ex. 10800 (3 hours)</b>", 
        true
      ),
      'Use SSL (https) In Requests' => array(
        'use_ssl', 
        'boolean', 
        "Check this option if requests made to the external site should use https instead of http.", 
        true
      )
    );

    foreach ( $settings_fields as $key => $callback_args ) {
      add_settings_field(
        $this->page . '['. $callback_args[0] . ']',
        $key,
        array( $this, 'field' ),
        $this->page,
        $this->option,
        array_combine( array( 'name', 'type', 'description', 'required' ), $callback_args )
      );
    }
  }

  /**
   * Settings page additional info.
   * Prints more details on the plugin settings page.
   */
  public function settings_info() {
    ?>
    <p>
      This plugin allows you to secure a site so that only users authenticated to a given external application may access it.  All of the following settings must be set correctly for this plugin to work correctly.
    </p>
    <hr>
    <?php
  }

  /**
   * Helper method for creating settings page form fields
   *
   * @param array $args an associative array containing the field options, with name, type, description, and required as keys
   */
  public function field( $args ) {
    $required = false;
    extract( $args );

    $id = str_replace( array( '_', ' ' ), '-', $name );

    switch ( $type ) {
      case 'boolean':
        ?>
        <input type="checkbox" id="lr-external-authentication-<?php echo $id; ?>" name="lr_external_authentication[<?php echo $name; ?>]" value="1" <?php checked( (bool) $this->options[$name] ); ?> />
        <?php
        break;
      default:
        ?>
        <input type="<?php echo $type; ?>" id="lr-external-authentication-<?php echo $id; ?>" name="lr_external_authentication[<?php echo $name; ?>]" value="<?php echo esc_attr( $this->options[$name] ); ?>">
        <?php
    }

    if ( $required ) {
      ?>
      <label for="lr-external-authentication-<?php echo $id; ?>">Required</label>
      <?php
    }

    ?>
    <br />
    <p class="description"><?php echo $description; ?></p>
    <?php
  }

  /**
   * Sanitize user input in settings page.
   *
   * @param  array $option user input
   * @return array sanitized input
   */
  public function sanitize_field( $option ) {
    $input = wp_parse_args( $option, array(
      'ext_site'                 => '',
      'ext_site_redirector_path' => '',
      'ext_site_session_path'    => '',
      'ext_site_secret_key'      => '',
      'ext_site_token_iss'       => '',
      'cookie_prefix'            => '',
      'session_expire'           => 0,
      'use_ssl'                  => false
    ) );

    $sanitized_input = array(
      'ext_site'                 => sanitize_text_field( $input['ext_site'] ),
      'ext_site_redirector_path' => sanitize_text_field( $input['ext_site_redirector_path'] ),
      'ext_site_session_path'    => sanitize_text_field( $input['ext_site_session_path'] ),
      'ext_site_secret_key'      => sanitize_text_field( $input['ext_site_secret_key'] ),
      'ext_site_token_iss'       => sanitize_text_field( $input['ext_site_token_iss'] ),
      'cookie_prefix'            => sanitize_text_field( $input['cookie_prefix'] ),
      'session_expire'           => intval( sanitize_text_field( $input['session_expire'] ) ),
      'use_ssl'                  => ! empty( $input['use_ssl'] )
    );

    return $sanitized_input;
  }

  /**
   * Settings page.
   */
  public function settings_page() {
    ?>
    <div class="wrap">
      <h2>LR External Authentication</h2>
      <hr />
      <form method="post" action="options.php">
        <?php
        settings_fields( $this->option );
        do_settings_sections( $this->page );
        submit_button();
        ?>
      </form>
    </div>
    <?php
  }
}
