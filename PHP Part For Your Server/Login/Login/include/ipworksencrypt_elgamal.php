<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - Elgamal Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_Elgamal {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_elgamal_open(IPWORKSENCRYPT_OEMKEY_43);
    ipworksencrypt_elgamal_register_callback($this->handle, 1, array($this, 'fireError'));
  }
  
  public function __destruct() {
    ipworksencrypt_elgamal_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_elgamal_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_elgamal_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_elgamal_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_elgamal_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new key.
  *
  * @access   public
  */
  public function doCreateKey() {
    $ret = ipworksencrypt_elgamal_do_createkey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the input data using the specified private key.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_elgamal_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the input data using the recipient's public key.
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_elgamal_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_elgamal_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_elgamal_get($this->handle, 0);
  }
 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_elgamal_get($this->handle, 1 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_elgamal_get($this->handle, 2 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the G parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getKeyG() {
    return ipworksencrypt_elgamal_get($this->handle, 3 );
  }
 /**
  * Represents the G parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyG($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the P parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getKeyP() {
    return ipworksencrypt_elgamal_get($this->handle, 4 );
  }
 /**
  * Represents the P parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyP($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  */
  public function getKeyPrivateKey() {
    return ipworksencrypt_elgamal_get($this->handle, 5 );
  }
 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPrivateKey($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getKeyPublicKey() {
    return ipworksencrypt_elgamal_get($this->handle, 6 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPublicKey($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the X parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getKeyX() {
    return ipworksencrypt_elgamal_get($this->handle, 7 );
  }
 /**
  * Represents the X parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyX($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Y parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getKeyY() {
    return ipworksencrypt_elgamal_get($this->handle, 8 );
  }
 /**
  * Represents the Y parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyY($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_elgamal_get($this->handle, 9 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output message after processing.
  *
  * @access   public
  */
  public function getOutputMessage() {
    return ipworksencrypt_elgamal_get($this->handle, 10 );
  }


 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_elgamal_get($this->handle, 11 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the G parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getRecipientKeyG() {
    return ipworksencrypt_elgamal_get($this->handle, 12 );
  }
 /**
  * Represents the G parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyG($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the P parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getRecipientKeyP() {
    return ipworksencrypt_elgamal_get($this->handle, 13 );
  }
 /**
  * Represents the P parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyP($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getRecipientKeyPublicKey() {
    return ipworksencrypt_elgamal_get($this->handle, 14 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyPublicKey($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Y parameter for the Elgamal algorithm.
  *
  * @access   public
  */
  public function getRecipientKeyY() {
    return ipworksencrypt_elgamal_get($this->handle, 15 );
  }
 /**
  * Represents the Y parameter for the Elgamal algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyY($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  */
  public function getUseHex() {
    return ipworksencrypt_elgamal_get($this->handle, 16 );
  }
 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseHex($value) {
    $ret = ipworksencrypt_elgamal_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_elgamal_get_last_error($this->handle));
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
