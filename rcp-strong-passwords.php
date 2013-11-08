<?php
/*
 Plugin Name: Restrict Content Pro - Enforce Strong Passwords
 Description: Forces users to register with strong passwords
 Author: Pippin Williamson
 Contributors: mordauk
 Version: 1.0
*/

class RCP_Strong_Passwords {
	
	/**
	 * Get things going
	 *
	 * @since	1.0
	 * @return	void
	 */
	public function __construct() {

		add_action( 'rcp_form_errors', array( $this, 'check_password' ) );

	}

	/**
	 * Checks for a strong password during registration
	 *
	 * @since	1.0
	 * @param	$data Data sent from the registration form
	 * @return	void
	 */
	public function check_password( $data ) {
		if ( $this->password_strength( $data['rcp_user_pass'], $data['rcp_user_login'] ) != 4 ) {
			rcp_errors()->add( 'weak_password', __( 'Please use a strong password', 'rcp' ), 'register' );
		}
	}

	/**
	 * Check for password strength
	 *
	 * @since	1.0
	 * @param	$pass     string The password
	 * @param	$username string The user's username
	 * @return	integer	1 = very weak; 2 = weak; 3 = medium; 4 = strong
	 */
	function password_strength( $pass, $username ) {
		$h = 1; $e = 2; $b = 3; $a = 4; $d = 0; $g = null; $c = null;
		if ( strlen( $pass ) < 4 )
			return $h;
		if ( strtolower( $pass ) == strtolower( $username ) )
			return $e;
		if ( preg_match( "/[0-9]/", $pass ) )
			$d += 10;
		if ( preg_match( "/[a-z]/", $pass ) )
			$d += 26;
		if ( preg_match( "/[A-Z]/", $pass ) )
			$d += 26;
		if ( preg_match( "/[^a-zA-Z0-9]/", $pass ) )
			$d += 31;
		$g = log( pow( $d, strlen( $pass ) ) );
		$c = $g / log( 2 );
		if ( $c < 40 )
			return $e;
		if ( $c < 56 )
			return $b;
		return $a;
	}

}

if( ! is_admin() ) {
	$rcp_strong_passwords = new RCP_Strong_Passwords;
}