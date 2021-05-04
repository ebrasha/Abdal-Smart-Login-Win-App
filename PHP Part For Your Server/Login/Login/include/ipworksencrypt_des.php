<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - DES Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_DES {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_des_open(IPWORKSENCRYPT_OEMKEY_39);
    ipworksencrypt_des_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_des_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_des_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_des_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_des_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_des_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_des_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the data.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_des_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts a block and returns the decrypted data.
  *
  * @access   public
  * @param    string    inputbuffer
  * @param    boolean    lastblock
  */
  public function doDecryptBlock($inputbuffer, $lastblock) {
    $ret = ipworksencrypt_des_do_decryptblock($this->handle, $inputbuffer, $lastblock);
		$err = ipworksencrypt_des_get_last_error_code($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the data.
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_des_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts data and returns the encrypted block.
  *
  * @access   public
  * @param    string    inputbuffer
  * @param    boolean    lastblock
  */
  public function doEncryptBlock($inputbuffer, $lastblock) {
    $ret = ipworksencrypt_des_do_encryptblock($this->handle, $inputbuffer, $lastblock);
		$err = ipworksencrypt_des_get_last_error_code($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_des_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_des_get($this->handle, 0);
  }
 /**
  * The cipher mode of operation.
  *
  * @access   public
  */
  public function getCipherMode() {
    return ipworksencrypt_des_get($this->handle, 1 );
  }
 /**
  * The cipher mode of operation.
  *
  * @access   public
  * @param    int   value
  */
  public function setCipherMode($value) {
    $ret = ipworksencrypt_des_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_des_get($this->handle, 2 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_des_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_des_get($this->handle, 3 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_des_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV).
  *
  * @access   public
  */
  public function getIV() {
    return ipworksencrypt_des_get($this->handle, 4 );
  }
 /**
  * The initialization vector (IV).
  *
  * @access   public
  * @param    string   value
  */
  public function setIV($value) {
    $ret = ipworksencrypt_des_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The secret key for the symmetric algorithm.
  *
  * @access   public
  */
  public function getKey() {
    return ipworksencrypt_des_get($this->handle, 5 );
  }
 /**
  * The secret key for the symmetric algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKey($value) {
    $ret = ipworksencrypt_des_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A password to generate the Key and IV .
  *
  * @access   public
  */
  public function getKeyPassword() {
    return ipworksencrypt_des_get($this->handle, 6 );
  }
 /**
  * A password to generate the Key and IV .
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPassword($value) {
    $ret = ipworksencrypt_des_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_des_get($this->handle, 7 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_des_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output message after processing.
  *
  * @access   public
  */
  public function getOutputMessage() {
    return ipworksencrypt_des_get($this->handle, 8 );
  }


 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_des_get($this->handle, 9 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_des_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The padding mode.
  *
  * @access   public
  */
  public function getPaddingMode() {
    return ipworksencrypt_des_get($this->handle, 10 );
  }
 /**
  * The padding mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setPaddingMode($value) {
    $ret = ipworksencrypt_des_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  */
  public function getUseHex() {
    return ipworksencrypt_des_get($this->handle, 11 );
  }
 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseHex($value) {
    $ret = ipworksencrypt_des_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_des_get_last_error($this->handle));
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
