<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - XMLSig Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_XMLSig {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_xmlsig_open(IPWORKSENCRYPT_OEMKEY_45);
    ipworksencrypt_xmlsig_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_xmlsig_register_callback($this->handle, 2, array($this, 'fireProgress'));
    ipworksencrypt_xmlsig_register_callback($this->handle, 3, array($this, 'fireSignatureInfo'));
    ipworksencrypt_xmlsig_register_callback($this->handle, 4, array($this, 'fireStatus'));
  }
  
  public function __destruct() {
    ipworksencrypt_xmlsig_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_xmlsig_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_xmlsig_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_xmlsig_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_xmlsig_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Processes events from the internal message queue.
  *
  * @access   public
  */
  public function doEvents() {
    $ret = ipworksencrypt_xmlsig_do_doevents($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_xmlsig_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs the XML.
  *
  * @access   public
  */
  public function doSign() {
    $ret = ipworksencrypt_xmlsig_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies signed XML.
  *
  * @access   public
  */
  public function doVerifySignature() {
    $ret = ipworksencrypt_xmlsig_do_verifysignature($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_xmlsig_get($this->handle, 0);
  }
 /**
  * The canonicalization method applied to the signature.
  *
  * @access   public
  */
  public function getCanonicalizationMethod() {
    return ipworksencrypt_xmlsig_get($this->handle, 1 );
  }
 /**
  * The canonicalization method applied to the signature.
  *
  * @access   public
  * @param    int   value
  */
  public function setCanonicalizationMethod($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_xmlsig_get($this->handle, 2 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_xmlsig_get($this->handle, 3 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_xmlsig_get($this->handle, 4 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_xmlsig_get($this->handle, 5 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_xmlsig_get($this->handle, 6 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The HMAC key used with the 'HMAC-SHA1' signing algorithm.
  *
  * @access   public
  */
  public function getHMACKey() {
    return ipworksencrypt_xmlsig_get($this->handle, 7 );
  }
 /**
  * The HMAC key used with the 'HMAC-SHA1' signing algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setHMACKey($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XML file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_xmlsig_get($this->handle, 8 );
  }
 /**
  * The XML file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XML to process.
  *
  * @access   public
  */
  public function getInputXML() {
    return ipworksencrypt_xmlsig_get($this->handle, 9 );
  }
 /**
  * The XML to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputXML($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_xmlsig_get($this->handle, 10 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output XML after processing.
  *
  * @access   public
  */
  public function getOutputXML() {
    return ipworksencrypt_xmlsig_get($this->handle, 11 );
  }
 /**
  * The output XML after processing.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputXML($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_xmlsig_get($this->handle, 12 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the Reference arrays.
  *
  * @access   public
  */
  public function getReferenceCount() {
    return ipworksencrypt_xmlsig_get($this->handle, 13 );
  }
 /**
  * The number of records in the Reference arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setReferenceCount($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property defines the hash algorithm to apply to the element specified by XMLElement .
  *
  * @access   public
  */
  public function getReferenceHashAlgorithm($referenceindex) {
    return ipworksencrypt_xmlsig_get($this->handle, 14 , $referenceindex);
  }
 /**
  * This property defines the hash algorithm to apply to the element specified by XMLElement .
  *
  * @access   public
  * @param    string   value
  */
  public function setReferenceHashAlgorithm($referenceindex, $value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 14, $value , $referenceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property holds the calculated hash value for the specified XMLElement .
  *
  * @access   public
  */
  public function getReferenceHashValue($referenceindex) {
    return ipworksencrypt_xmlsig_get($this->handle, 15 , $referenceindex);
  }


 /**
  * This property specifies a comma separated list of canonicalization algorithms to be applied to XMLElement .
  *
  * @access   public
  */
  public function getReferenceTransformAlgorithms($referenceindex) {
    return ipworksencrypt_xmlsig_get($this->handle, 16 , $referenceindex);
  }
 /**
  * This property specifies a comma separated list of canonicalization algorithms to be applied to XMLElement .
  *
  * @access   public
  * @param    string   value
  */
  public function setReferenceTransformAlgorithms($referenceindex, $value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 16, $value , $referenceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property is the URI of the reference.
  *
  * @access   public
  */
  public function getReferenceURI($referenceindex) {
    return ipworksencrypt_xmlsig_get($this->handle, 17 , $referenceindex);
  }
 /**
  * This property is the URI of the reference.
  *
  * @access   public
  * @param    string   value
  */
  public function setReferenceURI($referenceindex, $value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 17, $value , $referenceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property specifies XML element to sign or verify using XPath notation.
  *
  * @access   public
  */
  public function getReferenceXMLElement($referenceindex) {
    return ipworksencrypt_xmlsig_get($this->handle, 18 , $referenceindex);
  }
 /**
  * This property specifies XML element to sign or verify using XPath notation.
  *
  * @access   public
  * @param    string   value
  */
  public function setReferenceXMLElement($referenceindex, $value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 18, $value , $referenceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XPath of the signature.
  *
  * @access   public
  */
  public function getSignatureXPath() {
    return ipworksencrypt_xmlsig_get($this->handle, 19 );
  }
 /**
  * The XPath of the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignatureXPath($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getSignerCertEncoded() {
    return ipworksencrypt_xmlsig_get($this->handle, 20 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertEncoded($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  */
  public function getSignerCertStore() {
    return ipworksencrypt_xmlsig_get($this->handle, 21 );
  }
 /**
  * The name of the certificate store for the client certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStore($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  */
  public function getSignerCertStorePassword() {
    return ipworksencrypt_xmlsig_get($this->handle, 22 );
  }
 /**
  * If the certificate store is of a type that requires  a password, this property is used to specify that  password in order to open the certificate store.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertStorePassword($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  */
  public function getSignerCertStoreType() {
    return ipworksencrypt_xmlsig_get($this->handle, 23 );
  }
 /**
  * The type of certificate store for this certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignerCertStoreType($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getSignerCertSubject() {
    return ipworksencrypt_xmlsig_get($this->handle, 24 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignerCertSubject($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signing algorithm.
  *
  * @access   public
  */
  public function getSigningAlgorithm() {
    return ipworksencrypt_xmlsig_get($this->handle, 25 );
  }
 /**
  * The signing algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setSigningAlgorithm($value) {
    $ret = ipworksencrypt_xmlsig_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_xmlsig_get_last_error($this->handle));
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
  * @param    array   Array of event parameters: bytesprocessed, percentprocessed, operation, iseof    
  */
  public function fireProgress($param) {
    return $param;
  }

 /**
  * Fired when a signature is found.
  *
  * @access   public
  * @param    array   Array of event parameters: signatureid, signercertparsed    
  */
  public function fireSignatureInfo($param) {
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
