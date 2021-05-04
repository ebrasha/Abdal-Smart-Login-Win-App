<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - RSA Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_RSA {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_rsa_open(IPWORKSENCRYPT_OEMKEY_17);
    ipworksencrypt_rsa_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_rsa_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_rsa_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_rsa_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_rsa_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_rsa_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_rsa_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new key.
  *
  * @access   public
  */
  public function doCreateKey() {
    $ret = ipworksencrypt_rsa_do_createkey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the input data using the specified private key.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_rsa_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the input data using the recipient's public key.
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_rsa_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_rsa_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a hash signature.
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_rsa_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the signature for the specified data.
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_rsa_do_verifysignature($this->handle);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_rsa_get($this->handle, 0);
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_rsa_get($this->handle, 1 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_rsa_get($this->handle, 2 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_rsa_get($this->handle, 3 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_rsa_get($this->handle, 4 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_rsa_get($this->handle, 5 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash algorithm used for signing and signature verification.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return ipworksencrypt_rsa_get($this->handle, 6 );
  }
 /**
  * The hash algorithm used for signing and signature verification.
  *
  * @access   public
  * @param    int   value
  */
  public function setHashAlgorithm($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash signature.
  *
  * @access   public
  */
  public function getHashSignature() {
    return ipworksencrypt_rsa_get($this->handle, 7 );
  }
 /**
  * The hash signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashSignature($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash value of the data.
  *
  * @access   public
  */
  public function getHashValue() {
    return ipworksencrypt_rsa_get($this->handle, 8 );
  }
 /**
  * The hash value of the data.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashValue($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_rsa_get($this->handle, 9 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_rsa_get($this->handle, 10 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the D parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyD() {
    return ipworksencrypt_rsa_get($this->handle, 11 );
  }
 /**
  * Represents the D parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyD($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the DP parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyDP() {
    return ipworksencrypt_rsa_get($this->handle, 12 );
  }
 /**
  * Represents the DP parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyDP($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the DQ parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyDQ() {
    return ipworksencrypt_rsa_get($this->handle, 13 );
  }
 /**
  * Represents the DQ parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyDQ($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyExponent() {
    return ipworksencrypt_rsa_get($this->handle, 14 );
  }
 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyExponent($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the InverseQ parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyInverseQ() {
    return ipworksencrypt_rsa_get($this->handle, 15 );
  }
 /**
  * Represents the InverseQ parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyInverseQ($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyModulus() {
    return ipworksencrypt_rsa_get($this->handle, 16 );
  }
 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyModulus($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the P parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyP() {
    return ipworksencrypt_rsa_get($this->handle, 17 );
  }
 /**
  * Represents the P parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyP($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  */
  public function getKeyPrivateKey() {
    return ipworksencrypt_rsa_get($this->handle, 18 );
  }
 /**
  * This property is a PEM formatted private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPrivateKey($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getKeyPublicKey() {
    return ipworksencrypt_rsa_get($this->handle, 19 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPublicKey($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Q parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getKeyQ() {
    return ipworksencrypt_rsa_get($this->handle, 20 );
  }
 /**
  * Represents the Q parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyQ($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_rsa_get($this->handle, 21 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output message after processing.
  *
  * @access   public
  */
  public function getOutputMessage() {
    return ipworksencrypt_rsa_get($this->handle, 22 );
  }


 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_rsa_get($this->handle, 23 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getRecipientCertEncoded() {
    return ipworksencrypt_rsa_get($this->handle, 24 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertEncoded($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getRecipientCertStore() {
    return ipworksencrypt_rsa_get($this->handle, 25 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertStore($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getRecipientCertStorePassword() {
    return ipworksencrypt_rsa_get($this->handle, 26 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertStorePassword($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 26, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getRecipientCertStoreType() {
    return ipworksencrypt_rsa_get($this->handle, 27 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setRecipientCertStoreType($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getRecipientCertSubject() {
    return ipworksencrypt_rsa_get($this->handle, 28 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertSubject($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getRecipientKeyExponent() {
    return ipworksencrypt_rsa_get($this->handle, 29 );
  }
 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyExponent($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getRecipientKeyModulus() {
    return ipworksencrypt_rsa_get($this->handle, 30 );
  }
 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyModulus($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getRecipientKeyPublicKey() {
    return ipworksencrypt_rsa_get($this->handle, 31 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyPublicKey($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 31, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getSignerCertEncoded() {
    return ipworksencrypt_rsa_get($this->handle, 32 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertEncoded($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getSignerCertStore() {
    return ipworksencrypt_rsa_get($this->handle, 33 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStore($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 33, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getSignerCertStorePassword() {
    return ipworksencrypt_rsa_get($this->handle, 34 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStorePassword($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 34, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getSignerCertStoreType() {
    return ipworksencrypt_rsa_get($this->handle, 35 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignerCertStoreType($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getSignerCertSubject() {
    return ipworksencrypt_rsa_get($this->handle, 36 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertSubject($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyExponent() {
    return ipworksencrypt_rsa_get($this->handle, 37 );
  }
 /**
  * Represents the Exponent parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyExponent($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  */
  public function getSignerKeyModulus() {
    return ipworksencrypt_rsa_get($this->handle, 38 );
  }
 /**
  * Represents the Modulus parameter for the RSA algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyModulus($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 38, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  */
  public function getSignerKeyPublicKey() {
    return ipworksencrypt_rsa_get($this->handle, 39 );
  }
 /**
  * This property is a PEM formatted public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyPublicKey($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 39, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  */
  public function getUseHex() {
    return ipworksencrypt_rsa_get($this->handle, 40 );
  }
 /**
  * Whether input or output is hex encoded.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseHex($value) {
    $ret = ipworksencrypt_rsa_set($this->handle, 40, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_rsa_get_last_error($this->handle));
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
