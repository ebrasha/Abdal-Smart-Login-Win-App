<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - XMLEncrypt Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_XMLEncrypt {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_xmlencrypt_open(IPWORKSENCRYPT_OEMKEY_46);
    ipworksencrypt_xmlencrypt_register_callback($this->handle, 1, array($this, 'fireEncryptedDataInfo'));
    ipworksencrypt_xmlencrypt_register_callback($this->handle, 2, array($this, 'fireError'));
    ipworksencrypt_xmlencrypt_register_callback($this->handle, 3, array($this, 'fireProgress'));
    ipworksencrypt_xmlencrypt_register_callback($this->handle, 4, array($this, 'fireStatus'));
  }
  
  public function __destruct() {
    ipworksencrypt_xmlencrypt_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_xmlencrypt_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_xmlencrypt_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_xmlencrypt_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_xmlencrypt_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the XML.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = ipworksencrypt_xmlencrypt_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Processes events from the internal message queue.
  *
  * @access   public
  */
  public function doEvents() {
    $ret = ipworksencrypt_xmlencrypt_do_doevents($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the XML.
  *
  * @access   public
  */
  public function doEncrypt() {
    $ret = ipworksencrypt_xmlencrypt_do_encrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_xmlencrypt_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 0);
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 1 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 2 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 3 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 4 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 5 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the EncryptedDataDetail arrays.
  *
  * @access   public
  */
  public function getEncryptedDataDetailCount() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 6 );
  }
 /**
  * The number of records in the EncryptedDataDetail arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setEncryptedDataDetailCount($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is an optional identifier for the encrypted data.
  *
  * @access   public
  */
  public function getEncryptedDataDetailId($encrypteddatadetailindex) {
    return ipworksencrypt_xmlencrypt_get($this->handle, 7 , $encrypteddatadetailindex);
  }
 /**
  * This property is an optional identifier for the encrypted data.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptedDataDetailId($encrypteddatadetailindex, $value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 7, $value , $encrypteddatadetailindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property specifies the MIME type of the encrypted data.
  *
  * @access   public
  */
  public function getEncryptedDataDetailMIMEType($encrypteddatadetailindex) {
    return ipworksencrypt_xmlencrypt_get($this->handle, 8 , $encrypteddatadetailindex);
  }
 /**
  * This property specifies the MIME type of the encrypted data.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptedDataDetailMIMEType($encrypteddatadetailindex, $value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 8, $value , $encrypteddatadetailindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property specifies the scope of the encryption.
  *
  * @access   public
  */
  public function getEncryptedDataDetailScope($encrypteddatadetailindex) {
    return ipworksencrypt_xmlencrypt_get($this->handle, 9 , $encrypteddatadetailindex);
  }
 /**
  * This property specifies the scope of the encryption.
  *
  * @access   public
  * @param    int   value
  */
  public function setEncryptedDataDetailScope($encrypteddatadetailindex, $value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 9, $value , $encrypteddatadetailindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property specifies the XPath to the element which will be encrypted.
  *
  * @access   public
  */
  public function getEncryptedDataDetailXMLElement($encrypteddatadetailindex) {
    return ipworksencrypt_xmlencrypt_get($this->handle, 10 , $encrypteddatadetailindex);
  }
 /**
  * This property specifies the XPath to the element which will be encrypted.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptedDataDetailXMLElement($encrypteddatadetailindex, $value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 10, $value , $encrypteddatadetailindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Then encryption algorithm used when encrypting.
  *
  * @access   public
  */
  public function getEncryptingAlgorithm() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 11 );
  }
 /**
  * Then encryption algorithm used when encrypting.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptingAlgorithm($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XML file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 12 );
  }
 /**
  * The XML file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XML to process.
  *
  * @access   public
  */
  public function getInputXML() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 13 );
  }
 /**
  * The XML to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputXML($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 14 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output XML after processing.
  *
  * @access   public
  */
  public function getOutputXML() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 15 );
  }
 /**
  * The output XML after processing.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputXML($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 16 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getRecipientCertEncoded() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 17 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertEncoded($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getRecipientCertStore() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 18 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertStore($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getRecipientCertStorePassword() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 19 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertStorePassword($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getRecipientCertStoreType() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 20 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setRecipientCertStoreType($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getRecipientCertSubject() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 21 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setRecipientCertSubject($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The symmetric key used to encrypt and decrypt the XML.
  *
  * @access   public
  */
  public function getSymmetricKey() {
    return ipworksencrypt_xmlencrypt_get($this->handle, 22 );
  }
 /**
  * The symmetric key used to encrypt and decrypt the XML.
  *
  * @access   public
  * @param    string   value
  */
  public function setSymmetricKey($value) {
    $ret = ipworksencrypt_xmlencrypt_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlencrypt_get_last_error($this->handle));
    }
    return $ret;
  }


  
 /**
  * Fired once for each encrypted element when Decrypt is called.
  *
  * @access   public
  * @param    array   Array of event parameters: encrypteddataid, scope, mimetype    
  */
  public function fireEncryptedDataInfo($param) {
    return $param;
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
  * @param    array   Array of event parameters: bytesprocessed, percentprocessed, operation, iseof    
  */
  public function fireProgress($param) {
    return $param;
  }

 /**
  * Provides information about the current operation.
  *
  * @access   public
  * @param    array   Array of event parameters: message    
  */
  public function fireStatus($param) {
    return $param;
  }


}

?>
