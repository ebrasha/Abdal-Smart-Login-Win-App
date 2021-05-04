<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - Hash Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_Hash {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_hash_open(IPWORKSENCRYPT_OEMKEY_18);
    ipworksencrypt_hash_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_hash_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_hash_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_hash_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_hash_get_last_error_code($this->handle);
  }

 /**
  * Computes a hash.
  *
  * @access   public
  */
  public function doComputeHash() {
    $ret = ipworksencrypt_hash_do_computehash($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_hash_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_hash_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Computes the hash value of specified data.
  *
  * @access   public
  * @param    string    inputbuffer
  * @param    boolean    lastblock
  */
  public function doHashBlock($inputbuffer, $lastblock) {
    $ret = ipworksencrypt_hash_do_hashblock($this->handle, $inputbuffer, $lastblock);
		$err = ipworksencrypt_hash_get_last_error_code($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_hash_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_hash_get($this->handle, 0);
  }
 /**
  * The algorithm used to create the hash.
  *
  * @access   public
  */
  public function getAlgorithm() {
    return ipworksencrypt_hash_get($this->handle, 1 );
  }
 /**
  * The algorithm used to create the hash.
  *
  * @access   public
  * @param    int   value
  */
  public function setAlgorithm($value) {
    $ret = ipworksencrypt_hash_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether the hash value is hex encoded.
  *
  * @access   public
  */
  public function getEncodeHash() {
    return ipworksencrypt_hash_get($this->handle, 2 );
  }
 /**
  * Whether the hash value is hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setEncodeHash($value) {
    $ret = ipworksencrypt_hash_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash value.
  *
  * @access   public
  */
  public function getHashValue() {
    return ipworksencrypt_hash_get($this->handle, 3 );
  }


 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_hash_get($this->handle, 4 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_hash_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_hash_get($this->handle, 5 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_hash_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The secret key for the hash algorithm.
  *
  * @access   public
  */
  public function getKey() {
    return ipworksencrypt_hash_get($this->handle, 6 );
  }
 /**
  * The secret key for the hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKey($value) {
    $ret = ipworksencrypt_hash_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_hash_get_last_error($this->handle));
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

 /**
  * Fired as progress is made.
  *
  * @access   public
  * @param    array   Array of event parameters: bytesprocessed, percentprocessed    
  */
  public function fireProgress($param) {
    return $param;
  }


}

?>
