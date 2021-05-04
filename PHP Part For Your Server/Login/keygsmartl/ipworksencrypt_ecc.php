<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - ECC Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_ECC {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_ecc_open(IPWORKSENCRYPT_OEMKEY_15);
    ipworksencrypt_ecc_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_ecc_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_ecc_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_ecc_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_ecc_get_last_error_code($this->handle);
  }

 /**
  * Computes a shared secret.
  *
  * @access   public
  */
  public function doComputeSecret() {
    $ret = ipworksencrypt_ecc_do_computesecret($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
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
    $ret = ipworksencrypt_ecc_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_ecc_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new key.
  *
  * @access   public
  */
  public function doCreateKey() {
    $ret = ipworksencrypt_ecc_do_createkey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_ecc_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a hash signature.
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_ecc_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the signature for the specified data.
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_ecc_do_verifysignature($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_ecc_get($this->handle, 0);
  }
 /**
  * The hash algorithm used for hash computation.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return ipworksencrypt_ecc_get($this->handle, 1 );
  }
 /**
  * The hash algorithm used for hash computation.
  *
  * @access   public
  * @param    int   value
  */
  public function setHashAlgorithm($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash signature.
  *
  * @access   public
  */
  public function getHashSignature() {
    return ipworksencrypt_ecc_get($this->handle, 2 );
  }
 /**
  * The hash signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashSignature($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash value of the data.
  *
  * @access   public
  */
  public function getHashValue() {
    return ipworksencrypt_ecc_get($this->handle, 3 );
  }
 /**
  * The hash value of the data.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashValue($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_ecc_get($this->handle, 4 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_ecc_get($this->handle, 5 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the curve being used.
  *
  * @access   public
  */
  public function getKeyCurve() {
    return ipworksencrypt_ecc_get($this->handle, 6 );
  }
 /**
  * Specifies the curve being used.
  *
  * @access   public
  * @param    int   value
  */
  public function setKeyCurve($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represent the private key (K) parameter.
  *
  * @access   public
  */
  public function getKeyK() {
    return ipworksencrypt_ecc_get($this->handle, 7 );
  }
 /**
  * Represent the private key (K) parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyK($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  */
  public function getKeyPrivateKey() {
    return ipworksencrypt_ecc_get($this->handle, 8 );
  }
 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPrivateKey($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getKeyPublicKey() {
    return ipworksencrypt_ecc_get($this->handle, 9 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPublicKey($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  */
  public function getKeyRx() {
    return ipworksencrypt_ecc_get($this->handle, 10 );
  }
 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyRx($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  */
  public function getKeyRy() {
    return ipworksencrypt_ecc_get($this->handle, 11 );
  }
 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyRy($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The key derivation function.
  *
  * @access   public
  */
  public function getKeyDerivationFunction() {
    return ipworksencrypt_ecc_get($this->handle, 12 );
  }
 /**
  * The key derivation function.
  *
  * @access   public
  * @param    int   value
  */
  public function setKeyDerivationFunction($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the curve being used.
  *
  * @access   public
  */
  public function getRecipientKeyCurve() {
    return ipworksencrypt_ecc_get($this->handle, 13 );
  }
 /**
  * Specifies the curve being used.
  *
  * @access   public
  * @param    int   value
  */
  public function setRecipientKeyCurve($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getRecipientKeyPublicKey() {
    return ipworksencrypt_ecc_get($this->handle, 14 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyPublicKey($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  */
  public function getRecipientKeyRx() {
    return ipworksencrypt_ecc_get($this->handle, 15 );
  }
 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyRx($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  */
  public function getRecipientKeyRy() {
    return ipworksencrypt_ecc_get($this->handle, 16 );
  }
 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyRy($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The computed shared secret.
  *
  * @access   public
  */
  public function getSharedSecret() {
    return ipworksencrypt_ecc_get($this->handle, 17 );
  }


 /**
  * Specifies the curve being used.
  *
  * @access   public
  */
  public function getSignerKeyCurve() {
    return ipworksencrypt_ecc_get($this->handle, 18 );
  }
 /**
  * Specifies the curve being used.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignerKeyCurve($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getSignerKeyPublicKey() {
    return ipworksencrypt_ecc_get($this->handle, 19 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyPublicKey($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  */
  public function getSignerKeyRx() {
    return ipworksencrypt_ecc_get($this->handle, 20 );
  }
 /**
  * Represents the public key's Rx parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyRx($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  */
  public function getSignerKeyRy() {
    return ipworksencrypt_ecc_get($this->handle, 21 );
  }
 /**
  * Represents the public key's Ry parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyRy($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether HashValue and HashSignature are hex encoded.
  *
  * @access   public
  */
  public function getUseHex() {
    return ipworksencrypt_ecc_get($this->handle, 22 );
  }
 /**
  * Whether HashValue and HashSignature are hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseHex($value) {
    $ret = ipworksencrypt_ecc_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_ecc_get_last_error($this->handle));
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
