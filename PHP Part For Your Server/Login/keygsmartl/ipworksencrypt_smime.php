<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - SMIME Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_SMIME {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_smime_open(IPWORKSENCRYPT_OEMKEY_79);
    ipworksencrypt_smime_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_smime_register_callback($this->handle, 2, array($this, 'fireRecipientInfo'));
    ipworksencrypt_smime_register_callback($this->handle, 3, array($this, 'fireSignerCertInfo'));
  }
  
  public function __destruct() {
    ipworksencrypt_smime_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_smime_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_smime_get_last_error_code($this->handle);
  }

 /**
  * Used to add recipient certificates used to encrypt messages.
  *
  * @access   public
  * @param    string    certencoded
  */
  public function doAddRecipientCert($certencoded) {
    $ret = ipworksencrypt_smime_do_addrecipientcert($this->handle, $certencoded);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
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
    $ret = ipworksencrypt_smime_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_smime_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the current Message .
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_smime_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts and verifies the signature of the current Message .
  *
  * @access   public
  */
  public function doDecryptAndVerifySignature() {
    $ret = ipworksencrypt_smime_do_decryptandverifysignature($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the contents of a file.
  *
  * @access   public
  * @param    string    inputfile
  * @param    string    outputfile
  */
  public function doDecryptFile($inputfile, $outputfile) {
    $ret = ipworksencrypt_smime_do_decryptfile($this->handle, $inputfile, $outputfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the current Message .
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_smime_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the contents of a file.
  *
  * @access   public
  * @param    string    inputfile
  * @param    string    outputfile
  */
  public function doEncryptFile($inputfile, $outputfile) {
    $ret = ipworksencrypt_smime_do_encryptfile($this->handle, $inputfile, $outputfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Gets the recipient infos for an encrypted message.
  *
  * @access   public
  */
  public function doGetRecipientInfo() {
    $ret = ipworksencrypt_smime_do_getrecipientinfo($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component properties.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_smime_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs the current Message .
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_smime_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs and encrypts the current Message .
  *
  * @access   public
  */
  public function doSignAndEncrypt() {
    $ret = ipworksencrypt_smime_do_signandencrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the signature of the current Message .
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_smime_do_verifysignature($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_smime_get($this->handle, 0);
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_smime_get($this->handle, 1 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_smime_get($this->handle, 2 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_smime_get($this->handle, 3 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_smime_get($this->handle, 4 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_smime_get($this->handle, 5 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to include a detached signature when signing a message.
  *
  * @access   public
  */
  public function getDetachedSignature() {
    return ipworksencrypt_smime_get($this->handle, 6 );
  }
 /**
  * Specifies whether to include a detached signature when signing a message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setDetachedSignature($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Textual description of the encrypting algorithm.
  *
  * @access   public
  */
  public function getEncryptingAlgorithm() {
    return ipworksencrypt_smime_get($this->handle, 7 );
  }
 /**
  * Textual description of the encrypting algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptingAlgorithm($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to include the signer's certificate with the signed message.
  *
  * @access   public
  */
  public function getIncludeCertificate() {
    return ipworksencrypt_smime_get($this->handle, 8 );
  }
 /**
  * Specifies whether to include the signer's certificate with the signed message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIncludeCertificate($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to include the signer's certificate chain with the signed message.
  *
  * @access   public
  */
  public function getIncludeChain() {
    return ipworksencrypt_smime_get($this->handle, 9 );
  }
 /**
  * Specifies whether to include the signer's certificate chain with the signed message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIncludeChain($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The headers of the MIME entity inside the encrypted or signed message.
  *
  * @access   public
  */
  public function getInternalHeaders() {
    return ipworksencrypt_smime_get($this->handle, 10 );
  }
 /**
  * The headers of the MIME entity inside the encrypted or signed message.
  *
  * @access   public
  * @param    string   value
  */
  public function setInternalHeaders($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The fully encoded or decoded S/MIME message.
  *
  * @access   public
  */
  public function getMessage() {
    return ipworksencrypt_smime_get($this->handle, 11 );
  }
 /**
  * The fully encoded or decoded S/MIME message.
  *
  * @access   public
  * @param    string   value
  */
  public function setMessage($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether or not the current message is encrypted.
  *
  * @access   public
  */
  public function getMessageEncrypted() {
    return ipworksencrypt_smime_get($this->handle, 12 );
  }


 /**
  * The number of records in the MessageHeader arrays.
  *
  * @access   public
  */
  public function getMessageHeaderCount() {
    return ipworksencrypt_smime_get($this->handle, 13 );
  }
 /**
  * The number of records in the MessageHeader arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setMessageHeaderCount($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property contains the name of the HTTP header (same case as it is delivered).
  *
  * @access   public
  */
  public function getMessageHeaderField($messageheaderindex) {
    return ipworksencrypt_smime_get($this->handle, 14 , $messageheaderindex);
  }
 /**
  * This property contains the name of the HTTP header (same case as it is delivered).
  *
  * @access   public
  * @param    string   value
  */
  public function setMessageHeaderField($messageheaderindex, $value) {
    $ret = ipworksencrypt_smime_set($this->handle, 14, $value , $messageheaderindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property contains the header contents.
  *
  * @access   public
  */
  public function getMessageHeaderValue($messageheaderindex) {
    return ipworksencrypt_smime_get($this->handle, 15 , $messageheaderindex);
  }
 /**
  * This property contains the header contents.
  *
  * @access   public
  * @param    string   value
  */
  public function setMessageHeaderValue($messageheaderindex, $value) {
    $ret = ipworksencrypt_smime_set($this->handle, 15, $value , $messageheaderindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * String version of headers from the SMIME message.
  *
  * @access   public
  */
  public function getMessageHeadersString() {
    return ipworksencrypt_smime_get($this->handle, 16 );
  }
 /**
  * String version of headers from the SMIME message.
  *
  * @access   public
  * @param    string   value
  */
  public function setMessageHeadersString($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether or not the current message is signed.
  *
  * @access   public
  */
  public function getMessageSigned() {
    return ipworksencrypt_smime_get($this->handle, 17 );
  }


 /**
  * The number of records in the RecipientCert arrays.
  *
  * @access   public
  */
  public function getRecipientCertCount() {
    return ipworksencrypt_smime_get($this->handle, 18 );
  }
 /**
  * The number of records in the RecipientCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setRecipientCertCount($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getRecipientCertEncoded($recipientcertindex) {
    return ipworksencrypt_smime_get($this->handle, 19 , $recipientcertindex);
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertEncoded($recipientcertindex, $value) {
    $ret = ipworksencrypt_smime_set($this->handle, 19, $value , $recipientcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getSignerCertEncoded() {
    return ipworksencrypt_smime_get($this->handle, 20 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertEncoded($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The issuer of the certificate.
  *
  * @access   public
  */
  public function getSignerCertIssuer() {
    return ipworksencrypt_smime_get($this->handle, 21 );
  }


 /**
  * The serial number of the certificate encoded as a  string.
  *
  * @access   public
  */
  public function getSignerCertSerialNumber() {
    return ipworksencrypt_smime_get($this->handle, 22 );
  }


 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getSignerCertSubject() {
    return ipworksencrypt_smime_get($this->handle, 23 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertSubject($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SignerCertChain arrays.
  *
  * @access   public
  */
  public function getSignerCertChainCount() {
    return ipworksencrypt_smime_get($this->handle, 24 );
  }


 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getSignerCertChainEncoded($signercertchainindex) {
    return ipworksencrypt_smime_get($this->handle, 25 , $signercertchainindex);
  }


 /**
  * Textual description of the signature hash algorithm.
  *
  * @access   public
  */
  public function getSigningAlgorithm() {
    return ipworksencrypt_smime_get($this->handle, 26 );
  }
 /**
  * Textual description of the signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSigningAlgorithm($value) {
    $ret = ipworksencrypt_smime_set($this->handle, 26, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_smime_get_last_error($this->handle));
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
  * Fired for each recipient certificate of the encrypted message.
  *
  * @access   public
  * @param    array   Array of event parameters: issuer, serialnumber, encryptionalgorithm    
  */
  public function fireRecipientInfo($param) {
    return $param;
  }

 /**
  * Fired during verification of the signed message.
  *
  * @access   public
  * @param    array   Array of event parameters: issuer, serialnumber    
  */
  public function fireSignerCertInfo($param) {
    return $param;
  }


}

?>
