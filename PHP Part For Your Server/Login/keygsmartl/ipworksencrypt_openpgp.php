<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - OpenPGP Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_OpenPGP {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_openpgp_open(IPWORKSENCRYPT_OEMKEY_20);
    ipworksencrypt_openpgp_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_openpgp_register_callback($this->handle, 2, array($this, 'fireKeyPassphrase'));
    ipworksencrypt_openpgp_register_callback($this->handle, 3, array($this, 'fireProgress'));
    ipworksencrypt_openpgp_register_callback($this->handle, 4, array($this, 'fireRecipientInfo'));
    ipworksencrypt_openpgp_register_callback($this->handle, 5, array($this, 'fireSignatureInfo'));
    ipworksencrypt_openpgp_register_callback($this->handle, 6, array($this, 'fireStatus'));
    ipworksencrypt_openpgp_register_callback($this->handle, 7, array($this, 'fireVerificationStatus'));
  }
  
  public function __destruct() {
    ipworksencrypt_openpgp_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_openpgp_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_openpgp_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_openpgp_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_openpgp_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the message.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_openpgp_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts and verifies the signature of the message.
  *
  * @access   public
  */
  public function doDecryptAndVerifySignature() {
    $ret = ipworksencrypt_openpgp_do_decryptandverifysignature($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the message.
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_openpgp_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Gets recipient information for an encrypted message.
  *
  * @access   public
  */
  public function doGetRecipientInfo() {
    $ret = ipworksencrypt_openpgp_do_getrecipientinfo($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component properties.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_openpgp_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs the message.
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_openpgp_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs and encrypts the current message.
  *
  * @access   public
  */
  public function doSignAndEncrypt() {
    $ret = ipworksencrypt_openpgp_do_signandencrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the signature of the current message.
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_openpgp_do_verifysignature($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_openpgp_get($this->handle, 0);
  }
 /**
  * Specifies whether to use ASCII armor to encode the output message.
  *
  * @access   public
  */
  public function getASCIIArmor() {
    return ipworksencrypt_openpgp_get($this->handle, 1 );
  }
 /**
  * Specifies whether to use ASCII armor to encode the output message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setASCIIArmor($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether or not to create a cleartext signature.
  *
  * @access   public
  */
  public function getClearSignature() {
    return ipworksencrypt_openpgp_get($this->handle, 2 );
  }
 /**
  * Specifies whether or not to create a cleartext signature.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setClearSignature($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The compression algorithm used.
  *
  * @access   public
  */
  public function getCompressionMethod() {
    return ipworksencrypt_openpgp_get($this->handle, 3 );
  }
 /**
  * The compression algorithm used.
  *
  * @access   public
  * @param    string   value
  */
  public function setCompressionMethod($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether or not to generate a detached signature when signing a message.
  *
  * @access   public
  */
  public function getDetachedSignature() {
    return ipworksencrypt_openpgp_get($this->handle, 4 );
  }
 /**
  * Specifies whether or not to generate a detached signature when signing a message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setDetachedSignature($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The encryption algorithm used when encrypting.
  *
  * @access   public
  */
  public function getEncryptingAlgorithm() {
    return ipworksencrypt_openpgp_get($this->handle, 5 );
  }
 /**
  * The encryption algorithm used when encrypting.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptingAlgorithm($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_openpgp_get($this->handle, 6 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_openpgp_get($this->handle, 7 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the Key arrays.
  *
  * @access   public
  */
  public function getKeyCount() {
    return ipworksencrypt_openpgp_get($this->handle, 8 );
  }
 /**
  * The number of records in the Key arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKeyCount($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The key.
  *
  * @access   public
  */
  public function getKeyEncoded($keyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 9 , $keyindex);
  }
 /**
  * The key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyEncoded($keyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 9, $value , $keyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The location of the keyring.
  *
  * @access   public
  */
  public function getKeyKeyring($keyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 10 , $keyindex);
  }
 /**
  * The location of the keyring.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyKeyring($keyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 10, $value , $keyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The passphrase for the key's secret key (if any).
  *
  * @access   public
  */
  public function getKeyPassphrase($keyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 11 , $keyindex);
  }
 /**
  * The passphrase for the key's secret key (if any).
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPassphrase($keyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 11, $value , $keyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user Id of the key.
  *
  * @access   public
  */
  public function getKeyUserId($keyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 12 , $keyindex);
  }
 /**
  * The user Id of the key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyUserId($keyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 12, $value , $keyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the MessageHeader arrays.
  *
  * @access   public
  */
  public function getMessageHeaderCount() {
    return ipworksencrypt_openpgp_get($this->handle, 13 );
  }
 /**
  * The number of records in the MessageHeader arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setMessageHeaderCount($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property contains the name of the HTTP header (same case as it is delivered).
  *
  * @access   public
  */
  public function getMessageHeaderField($messageheaderindex) {
    return ipworksencrypt_openpgp_get($this->handle, 14 , $messageheaderindex);
  }
 /**
  * This property contains the name of the HTTP header (same case as it is delivered).
  *
  * @access   public
  * @param    string   value
  */
  public function setMessageHeaderField($messageheaderindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 14, $value , $messageheaderindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property contains the header contents.
  *
  * @access   public
  */
  public function getMessageHeaderValue($messageheaderindex) {
    return ipworksencrypt_openpgp_get($this->handle, 15 , $messageheaderindex);
  }
 /**
  * This property contains the header contents.
  *
  * @access   public
  * @param    string   value
  */
  public function setMessageHeaderValue($messageheaderindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 15, $value , $messageheaderindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_openpgp_get($this->handle, 16 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output message after processing.
  *
  * @access   public
  */
  public function getOutputMessage() {
    return ipworksencrypt_openpgp_get($this->handle, 17 );
  }
 /**
  * The output message after processing.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputMessage($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_openpgp_get($this->handle, 18 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the RecipientKey arrays.
  *
  * @access   public
  */
  public function getRecipientKeyCount() {
    return ipworksencrypt_openpgp_get($this->handle, 19 );
  }
 /**
  * The number of records in the RecipientKey arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setRecipientKeyCount($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The key.
  *
  * @access   public
  */
  public function getRecipientKeyEncoded($recipientkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 20 , $recipientkeyindex);
  }
 /**
  * The key.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyEncoded($recipientkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 20, $value , $recipientkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The location of the keyring.
  *
  * @access   public
  */
  public function getRecipientKeyKeyring($recipientkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 21 , $recipientkeyindex);
  }
 /**
  * The location of the keyring.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyKeyring($recipientkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 21, $value , $recipientkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user Id of the key.
  *
  * @access   public
  */
  public function getRecipientKeyUserId($recipientkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 22 , $recipientkeyindex);
  }
 /**
  * The user Id of the key.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientKeyUserId($recipientkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 22, $value , $recipientkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SignerKey arrays.
  *
  * @access   public
  */
  public function getSignerKeyCount() {
    return ipworksencrypt_openpgp_get($this->handle, 23 );
  }
 /**
  * The number of records in the SignerKey arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignerKeyCount($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The key.
  *
  * @access   public
  */
  public function getSignerKeyEncoded($signerkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 24 , $signerkeyindex);
  }
 /**
  * The key.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyEncoded($signerkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 24, $value , $signerkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The location of the keyring.
  *
  * @access   public
  */
  public function getSignerKeyKeyring($signerkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 25 , $signerkeyindex);
  }
 /**
  * The location of the keyring.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyKeyring($signerkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 25, $value , $signerkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user Id of the key.
  *
  * @access   public
  */
  public function getSignerKeyUserId($signerkeyindex) {
    return ipworksencrypt_openpgp_get($this->handle, 26 , $signerkeyindex);
  }
 /**
  * The user Id of the key.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerKeyUserId($signerkeyindex, $value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 26, $value , $signerkeyindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signature hash algorithm used when signing.
  *
  * @access   public
  */
  public function getSigningAlgorithm() {
    return ipworksencrypt_openpgp_get($this->handle, 27 );
  }
 /**
  * The signature hash algorithm used when signing.
  *
  * @access   public
  * @param    string   value
  */
  public function setSigningAlgorithm($value) {
    $ret = ipworksencrypt_openpgp_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_openpgp_get_last_error($this->handle));
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
  * Fired if the passphrase of current key is incorrect or empty.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, keyid, passphrase    
  */
  public function fireKeyPassphrase($param) {
    return $param;
  }

 /**
  * Fired as progress is made.
  *
  * @access   public
  * @param    array   Array of event parameters: bytesprocessed, percentprocessed, operation, iseof    
  */
  public function fireProgress($param) {
    return $param;
  }

 /**
  * Fired for each recipient key of the encrypted message.
  *
  * @access   public
  * @param    array   Array of event parameters: keyid, publickeyalgorithm    
  */
  public function fireRecipientInfo($param) {
    return $param;
  }

 /**
  * Fired during verification of the signed message.
  *
  * @access   public
  * @param    array   Array of event parameters: keyid, signingalgorithm, publickeyalgorithm    
  */
  public function fireSignatureInfo($param) {
    return $param;
  }

 /**
  * Shows the progress of the operation.
  *
  * @access   public
  * @param    array   Array of event parameters: message    
  */
  public function fireStatus($param) {
    return $param;
  }

 /**
  * Fired after verification of the signed message.
  *
  * @access   public
  * @param    array   Array of event parameters: keyid, status    
  */
  public function fireVerificationStatus($param) {
    return $param;
  }


}

?>
