<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - DSA Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_DSA {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_dsa_open(IPWORKSENCRYPT_OEMKEY_41);
    ipworksencrypt_dsa_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_dsa_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_dsa_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_dsa_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_dsa_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_dsa_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_dsa_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new key.
  *
  * @access   public
  */
  public function doCreateKey() {
    $ret = ipworksencrypt_dsa_do_createkey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_dsa_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a hash signature.
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_dsa_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the signature for the specified data.
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_dsa_do_verifysignature($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_dsa_get($this->handle, 0);
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_dsa_get($this->handle, 1 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_dsa_get($this->handle, 2 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_dsa_get($this->handle, 3 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_dsa_get($this->handle, 4 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_dsa_get($this->handle, 5 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash algorithm used for hash computation.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return ipworksencrypt_dsa_get($this->handle, 6 );
  }
 /**
  * The hash algorithm used for hash computation.
  *
  * @access   public
  * @param    int   value
  */
  public function setHashAlgorithm($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash signature.
  *
  * @access   public
  */
  public function getHashSignature() {
    return ipworksencrypt_dsa_get($this->handle, 7 );
  }
 /**
  * The hash signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashSignature($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash value of the data.
  *
  * @access   public
  */
  public function getHashValue() {
    return ipworksencrypt_dsa_get($this->handle, 8 );
  }
 /**
  * The hash value of the data.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashValue($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_dsa_get($this->handle, 9 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_dsa_get($this->handle, 10 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the G parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getKeyG() {
    return ipworksencrypt_dsa_get($this->handle, 11 );
  }
 /**
  * Represents the G parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyG($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the P parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getKeyP() {
    return ipworksencrypt_dsa_get($this->handle, 12 );
  }
 /**
  * Represents the P parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyP($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  */
  public function getKeyPrivateKey() {
    return ipworksencrypt_dsa_get($this->handle, 13 );
  }
 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPrivateKey($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getKeyPublicKey() {
    return ipworksencrypt_dsa_get($this->handle, 14 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPublicKey($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Q parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getKeyQ() {
    return ipworksencrypt_dsa_get($this->handle, 15 );
  }
 /**
  * Represents the Q parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyQ($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the X parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getKeyX() {
    return ipworksencrypt_dsa_get($this->handle, 16 );
  }
 /**
  * Represents the X parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyX($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Y parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getKeyY() {
    return ipworksencrypt_dsa_get($this->handle, 17 );
  }
 /**
  * Represents the Y parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyY($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getSignerCertEncoded() {
    return ipworksencrypt_dsa_get($this->handle, 18 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertEncoded($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getSignerCertStore() {
    return ipworksencrypt_dsa_get($this->handle, 19 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStore($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getSignerCertStorePassword() {
    return ipworksencrypt_dsa_get($this->handle, 20 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStorePassword($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getSignerCertStoreType() {
    return ipworksencrypt_dsa_get($this->handle, 21 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignerCertStoreType($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getSignerCertSubject() {
    return ipworksencrypt_dsa_get($this->handle, 22 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertSubject($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the G parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyG() {
    return ipworksencrypt_dsa_get($this->handle, 23 );
  }
 /**
  * Represents the G parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyG($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the P parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyP() {
    return ipworksencrypt_dsa_get($this->handle, 24 );
  }
 /**
  * Represents the P parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyP($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getSignerKeyPublicKey() {
    return ipworksencrypt_dsa_get($this->handle, 25 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyPublicKey($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Q parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyQ() {
    return ipworksencrypt_dsa_get($this->handle, 26 );
  }
 /**
  * Represents the Q parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyQ($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 26, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Y parameter for the DSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyY() {
    return ipworksencrypt_dsa_get($this->handle, 27 );
  }
 /**
  * Represents the Y parameter for the DSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyY($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether HashValue and HashSignature are hex encoded.
  *
  * @access   public
  */
  public function getUseHex() {
    return ipworksencrypt_dsa_get($this->handle, 28 );
  }
 /**
  * Whether HashValue and HashSignature are hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseHex($value) {
    $ret = ipworksencrypt_dsa_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dsa_get_last_error($this->handle));
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
