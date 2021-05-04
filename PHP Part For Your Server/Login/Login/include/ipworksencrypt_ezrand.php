<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - EzRand Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_EzRand {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_ezrand_open(IPWORKSENCRYPT_OEMKEY_27);
    ipworksencrypt_ezrand_register_callback($this->handle, 1, array($this, 'fireError'));
  }
  
  public function __destruct() {
    ipworksencrypt_ezrand_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_ezrand_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_ezrand_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_ezrand_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_ezrand_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a sequence of random bytes.
  *
  * @access   public
  */
  public function doGetNextBytes() {
    $ret = ipworksencrypt_ezrand_do_getnextbytes($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a random integer.
  *
  * @access   public
  */
  public function doGetNextInt() {
    $ret = ipworksencrypt_ezrand_do_getnextint($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_ezrand_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_ezrand_get($this->handle, 0);
  }
 /**
  * The random number algorithm.
  *
  * @access   public
  */
  public function getAlgorithm() {
    return ipworksencrypt_ezrand_get($this->handle, 1 );
  }
 /**
  * The random number algorithm.
  *
  * @access   public
  * @param    int   value
  */
  public function setAlgorithm($value) {
    $ret = ipworksencrypt_ezrand_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The exclusive upper bound.
  *
  * @access   public
  */
  public function getMax() {
    return ipworksencrypt_ezrand_get($this->handle, 2 );
  }
 /**
  * The exclusive upper bound.
  *
  * @access   public
  * @param    int   value
  */
  public function setMax($value) {
    $ret = ipworksencrypt_ezrand_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The inclusive lower bound.
  *
  * @access   public
  */
  public function getMin() {
    return ipworksencrypt_ezrand_get($this->handle, 3 );
  }
 /**
  * The inclusive lower bound.
  *
  * @access   public
  * @param    int   value
  */
  public function setMin($value) {
    $ret = ipworksencrypt_ezrand_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The random byte array.
  *
  * @access   public
  */
  public function getRandBytes() {
    return ipworksencrypt_ezrand_get($this->handle, 4 );
  }


 /**
  * The length of the byte array to be generated.
  *
  * @access   public
  */
  public function getRandBytesLength() {
    return ipworksencrypt_ezrand_get($this->handle, 5 );
  }
 /**
  * The length of the byte array to be generated.
  *
  * @access   public
  * @param    int   value
  */
  public function setRandBytesLength($value) {
    $ret = ipworksencrypt_ezrand_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The random integer.
  *
  * @access   public
  */
  public function getRandInt() {
    return ipworksencrypt_ezrand_get($this->handle, 6 );
  }


 /**
  * The seed.
  *
  * @access   public
  */
  public function getSeed() {
    return ipworksencrypt_ezrand_get($this->handle, 7 );
  }
 /**
  * The seed.
  *
  * @access   public
  * @param    string   value
  */
  public function setSeed($value) {
    $ret = ipworksencrypt_ezrand_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ezrand_get_last_error($this->handle));
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
