<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - OneTimePassword Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_OneTimePassword {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_onetimepassword_open(IPWORKSENCRYPT_OEMKEY_76);
    ipworksencrypt_onetimepassword_register_callback($this->handle, 1, array($this, 'fireError'));
  }
  
  public function __destruct() {
    ipworksencrypt_onetimepassword_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_onetimepassword_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_onetimepassword_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_onetimepassword_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_onetimepassword_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a Time-Based or HMAC-Based One Time Password.
  *
  * @access   public
  */
  public function doCreatePassword() {
    $ret = ipworksencrypt_onetimepassword_do_createpassword($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Reset the variables to default value.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_onetimepassword_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Validates a Time-Based or HMAC-Based One Time Password.
  *
  * @access   public
  */
  public function doValidatePassword() {
    $ret = ipworksencrypt_onetimepassword_do_validatepassword($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_onetimepassword_get($this->handle, 0);
  }
 /**
  * The counter used for HMAC-Based One Time Password creation or validation.
  *
  * @access   public
  */
  public function getCounter() {
    return ipworksencrypt_onetimepassword_get($this->handle, 1 );
  }
 /**
  * The counter used for HMAC-Based One Time Password creation or validation.
  *
  * @access   public
  * @param    int64   value
  */
  public function setCounter($value) {
    $ret = ipworksencrypt_onetimepassword_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The HMAC-Based or Time-Based One Time Password.
  *
  * @access   public
  */
  public function getPassword() {
    return ipworksencrypt_onetimepassword_get($this->handle, 2 );
  }
 /**
  * The HMAC-Based or Time-Based One Time Password.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = ipworksencrypt_onetimepassword_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm used to create or validate the password.
  *
  * @access   public
  */
  public function getPasswordAlgorithm() {
    return ipworksencrypt_onetimepassword_get($this->handle, 3 );
  }
 /**
  * The algorithm used to create or validate the password.
  *
  * @access   public
  * @param    int   value
  */
  public function setPasswordAlgorithm($value) {
    $ret = ipworksencrypt_onetimepassword_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The Base32 encoded shared secret used when creating and validating a password.
  *
  * @access   public
  */
  public function getSecret() {
    return ipworksencrypt_onetimepassword_get($this->handle, 4 );
  }
 /**
  * The Base32 encoded shared secret used when creating and validating a password.
  *
  * @access   public
  * @param    string   value
  */
  public function setSecret($value) {
    $ret = ipworksencrypt_onetimepassword_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The time step (in seconds) used for Time-Based One Time Password creation or validation.
  *
  * @access   public
  */
  public function getTimeStep() {
    return ipworksencrypt_onetimepassword_get($this->handle, 5 );
  }
 /**
  * The time step (in seconds) used for Time-Based One Time Password creation or validation.
  *
  * @access   public
  * @param    int   value
  */
  public function setTimeStep($value) {
    $ret = ipworksencrypt_onetimepassword_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_onetimepassword_get_last_error($this->handle));
    }
    return $ret;
  }


  
 /**
  * Information about errors during data delivery.
  *
  * @access   public
  * @param    array   Array of event parameters: errorcode, description    
  */
  public function fireError($param) {
    return $param;
  }


}

?>
