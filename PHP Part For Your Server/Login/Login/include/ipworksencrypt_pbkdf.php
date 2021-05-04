<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - PBKDF Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_PBKDF {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_pbkdf_open(IPWORKSENCRYPT_OEMKEY_21);
    ipworksencrypt_pbkdf_register_callback($this->handle, 1, array($this, 'fireError'));
  }
  
  public function __destruct() {
    ipworksencrypt_pbkdf_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_pbkdf_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_pbkdf_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_pbkdf_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_pbkdf_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a derived key.
  *
  * @access   public
  */
  public function doCreateKey() {
    $ret = ipworksencrypt_pbkdf_do_createkey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_pbkdf_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_pbkdf_get($this->handle, 0);
  }
 /**
  * The underlying pseudorandom function.
  *
  * @access   public
  */
  public function getAlgorithm() {
    return ipworksencrypt_pbkdf_get($this->handle, 1 );
  }
 /**
  * The underlying pseudorandom function.
  *
  * @access   public
  * @param    int   value
  */
  public function setAlgorithm($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of iterations to perform.
  *
  * @access   public
  */
  public function getIterations() {
    return ipworksencrypt_pbkdf_get($this->handle, 2 );
  }
 /**
  * The number of iterations to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setIterations($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The derived key.
  *
  * @access   public
  */
  public function getKey() {
    return ipworksencrypt_pbkdf_get($this->handle, 3 );
  }


 /**
  * The desired length in bits of the derived key.
  *
  * @access   public
  */
  public function getKeyLength() {
    return ipworksencrypt_pbkdf_get($this->handle, 4 );
  }
 /**
  * The desired length in bits of the derived key.
  *
  * @access   public
  * @param    int   value
  */
  public function setKeyLength($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The master password from which a derived key is generated.
  *
  * @access   public
  */
  public function getPassword() {
    return ipworksencrypt_pbkdf_get($this->handle, 5 );
  }
 /**
  * The master password from which a derived key is generated.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The cryptographic salt.
  *
  * @access   public
  */
  public function getSalt() {
    return ipworksencrypt_pbkdf_get($this->handle, 6 );
  }
 /**
  * The cryptographic salt.
  *
  * @access   public
  * @param    string   value
  */
  public function setSalt($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The PBKDF version.
  *
  * @access   public
  */
  public function getVersion() {
    return ipworksencrypt_pbkdf_get($this->handle, 7 );
  }
 /**
  * The PBKDF version.
  *
  * @access   public
  * @param    int   value
  */
  public function setVersion($value) {
    $ret = ipworksencrypt_pbkdf_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_pbkdf_get_last_error($this->handle));
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
