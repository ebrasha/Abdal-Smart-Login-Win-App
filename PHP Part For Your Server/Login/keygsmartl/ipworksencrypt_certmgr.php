<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - CertMgr Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_CertMgr {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_certmgr_open(IPWORKSENCRYPT_OEMKEY_57);
    ipworksencrypt_certmgr_register_callback($this->handle, 1, array($this, 'fireCertChain'));
    ipworksencrypt_certmgr_register_callback($this->handle, 2, array($this, 'fireCertList'));
    ipworksencrypt_certmgr_register_callback($this->handle, 3, array($this, 'fireError'));
    ipworksencrypt_certmgr_register_callback($this->handle, 4, array($this, 'fireKeyList'));
    ipworksencrypt_certmgr_register_callback($this->handle, 5, array($this, 'fireStoreList'));
  }
  
  public function __destruct() {
    ipworksencrypt_certmgr_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_certmgr_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_certmgr_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_certmgr_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new self-signed certificate in the current store.
  *
  * @access   public
  * @param    string    certsubject
  * @param    int    serialnumber
  */
  public function doCreateCertificate($certsubject, $serialnumber) {
    $ret = ipworksencrypt_certmgr_do_createcertificate($this->handle, $certsubject, $serialnumber);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new keyset associated with the provided name.
  *
  * @access   public
  * @param    string    keyname
  */
  public function doCreateKey($keyname) {
    $ret = ipworksencrypt_certmgr_do_createkey($this->handle, $keyname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Deletes the currently selected certificate from the store.
  *
  * @access   public
  */
  public function doDeleteCertificate() {
    $ret = ipworksencrypt_certmgr_do_deletecertificate($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Deletes the keyset associated with the provided name.
  *
  * @access   public
  * @param    string    keyname
  */
  public function doDeleteKey($keyname) {
    $ret = ipworksencrypt_certmgr_do_deletekey($this->handle, $keyname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the current certificate to a PFX file.
  *
  * @access   public
  * @param    string    pfxfile
  * @param    string    password
  */
  public function doExportCertificate($pfxfile, $password) {
    $ret = ipworksencrypt_certmgr_do_exportcertificate($this->handle, $pfxfile, $password);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a new CSR to be sent to a signing authority.
  *
  * @access   public
  * @param    string    certsubject
  * @param    string    keyname
  */
  public function doGenerateCSR($certsubject, $keyname) {
    $ret = ipworksencrypt_certmgr_do_generatecsr($this->handle, $certsubject, $keyname);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Imports a certificate from a PFX file into the current certificate store.
  *
  * @access   public
  * @param    string    pfxfile
  * @param    string    password
  * @param    string    subject
  */
  public function doImportCertificate($pfxfile, $password, $subject) {
    $ret = ipworksencrypt_certmgr_do_importcertificate($this->handle, $pfxfile, $password, $subject);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Imports a signed CSR.
  *
  * @access   public
  * @param    string    signedcsr
  * @param    string    keyname
  */
  public function doImportSignedCSR($signedcsr, $keyname) {
    $ret = ipworksencrypt_certmgr_do_importsignedcsr($this->handle, $signedcsr, $keyname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new certificate in the current store, signed by the selected certificate.
  *
  * @access   public
  * @param    string    certsubject
  * @param    int    serialnumber
  */
  public function doIssueCertificate($certsubject, $serialnumber) {
    $ret = ipworksencrypt_certmgr_do_issuecertificate($this->handle, $certsubject, $serialnumber);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Lists certificate stores.
  *
  * @access   public
  */
  public function doListCertificateStores() {
    $ret = ipworksencrypt_certmgr_do_listcertificatestores($this->handle);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * List keysets in a CSP.
  *
  * @access   public
  */
  public function doListKeys() {
    $ret = ipworksencrypt_certmgr_do_listkeys($this->handle);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * List machine certificate stores.
  *
  * @access   public
  */
  public function doListMachineStores() {
    $ret = ipworksencrypt_certmgr_do_listmachinestores($this->handle);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * List certificates in a store.
  *
  * @access   public
  */
  public function doListStoreCertificates() {
    $ret = ipworksencrypt_certmgr_do_liststorecertificates($this->handle);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads a certificate from a file.
  *
  * @access   public
  * @param    string    filename
  */
  public function doReadCertificate($filename) {
    $ret = ipworksencrypt_certmgr_do_readcertificate($this->handle, $filename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets all certificate properties to their default values.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_certmgr_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the current certificate to a file.
  *
  * @access   public
  * @param    string    filename
  */
  public function doSaveCertificate($filename) {
    $ret = ipworksencrypt_certmgr_do_savecertificate($this->handle, $filename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Show certificate chain.
  *
  * @access   public
  */
  public function doShowCertificateChain() {
    $ret = ipworksencrypt_certmgr_do_showcertificatechain($this->handle);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a signed certificate from a CSR.
  *
  * @access   public
  * @param    string    csr
  * @param    int    serialnumber
  */
  public function doSignCSR($csr, $serialnumber) {
    $ret = ipworksencrypt_certmgr_do_signcsr($this->handle, $csr, $serialnumber);
		$err = ipworksencrypt_certmgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_certmgr_get($this->handle, 0);
  }
 /**
  * The date which this certificate becomes valid.
  *
  * @access   public
  */
  public function getCertEffectiveDate() {
    return ipworksencrypt_certmgr_get($this->handle, 1 );
  }


 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  */
  public function getCertEncoded() {
    return ipworksencrypt_certmgr_get($this->handle, 2 );
  }
 /**
  * The certificate (PEM/base64 encoded).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertEncoded($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The date the certificate expires.
  *
  * @access   public
  */
  public function getCertExpirationDate() {
    return ipworksencrypt_certmgr_get($this->handle, 3 );
  }


 /**
  * A comma-delimited list of extended key usage identifiers.
  *
  * @access   public
  */
  public function getCertExtendedKeyUsage() {
    return ipworksencrypt_certmgr_get($this->handle, 4 );
  }
 /**
  * A comma-delimited list of extended key usage identifiers.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertExtendedKeyUsage($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hex-encoded, 16-byte MD5 fingerprint of the certificate.
  *
  * @access   public
  */
  public function getCertFingerprint() {
    return ipworksencrypt_certmgr_get($this->handle, 5 );
  }


 /**
  * The issuer of the certificate.
  *
  * @access   public
  */
  public function getCertIssuer() {
    return ipworksencrypt_certmgr_get($this->handle, 6 );
  }


 /**
  * The password for the certificate's private key (if any).
  *
  * @access   public
  */
  public function getCertKeyPassword() {
    return ipworksencrypt_certmgr_get($this->handle, 7 );
  }
 /**
  * The password for the certificate's private key (if any).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertKeyPassword($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The private key of the certificate (if available).
  *
  * @access   public
  */
  public function getCertPrivateKey() {
    return ipworksencrypt_certmgr_get($this->handle, 8 );
  }


 /**
  * Shows whether a PrivateKey is available for the  selected certificate.
  *
  * @access   public
  */
  public function getCertPrivateKeyAvailable() {
    return ipworksencrypt_certmgr_get($this->handle, 9 );
  }


 /**
  * The name of the PrivateKey container for the  certificate (if available).
  *
  * @access   public
  */
  public function getCertPrivateKeyContainer() {
    return ipworksencrypt_certmgr_get($this->handle, 10 );
  }


 /**
  * The public key of the certificate.
  *
  * @access   public
  */
  public function getCertPublicKey() {
    return ipworksencrypt_certmgr_get($this->handle, 11 );
  }


 /**
  * Textual description of the public key algorithm of the  certificate.
  *
  * @access   public
  */
  public function getCertPublicKeyAlgorithm() {
    return ipworksencrypt_certmgr_get($this->handle, 12 );
  }
 /**
  * Textual description of the public key algorithm of the  certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertPublicKeyAlgorithm($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the certificate public key (in bits).
  *
  * @access   public
  */
  public function getCertPublicKeyLength() {
    return ipworksencrypt_certmgr_get($this->handle, 13 );
  }


 /**
  * The serial number of the certificate encoded as a  string.
  *
  * @access   public
  */
  public function getCertSerialNumber() {
    return ipworksencrypt_certmgr_get($this->handle, 14 );
  }


 /**
  * Text description of the signature algorithm of the  certificate.
  *
  * @access   public
  */
  public function getCertSignatureAlgorithm() {
    return ipworksencrypt_certmgr_get($this->handle, 15 );
  }


 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  */
  public function getCertSubject() {
    return ipworksencrypt_certmgr_get($this->handle, 16 );
  }
 /**
  * The subject of the certificate used for client authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubject($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A comma-separated lists of alternative subject names of the certificate.
  *
  * @access   public
  */
  public function getCertSubjectAltNames() {
    return ipworksencrypt_certmgr_get($this->handle, 17 );
  }


 /**
  * MD5 hash of the certificate.
  *
  * @access   public
  */
  public function getCertThumbprintMD5() {
    return ipworksencrypt_certmgr_get($this->handle, 18 );
  }


 /**
  * SHA1 hash of the certificate.
  *
  * @access   public
  */
  public function getCertThumbprintSHA1() {
    return ipworksencrypt_certmgr_get($this->handle, 19 );
  }


 /**
  * Text description of UsageFlags .
  *
  * @access   public
  */
  public function getCertUsage() {
    return ipworksencrypt_certmgr_get($this->handle, 20 );
  }
 /**
  * Text description of UsageFlags .
  *
  * @access   public
  * @param    string   value
  */
  public function setCertUsage($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Flags that show intended use for the certificate.
  *
  * @access   public
  */
  public function getCertUsageFlags() {
    return ipworksencrypt_certmgr_get($this->handle, 21 );
  }
 /**
  * Flags that show intended use for the certificate.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertUsageFlags($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The certificate's version number.
  *
  * @access   public
  */
  public function getCertVersion() {
    return ipworksencrypt_certmgr_get($this->handle, 22 );
  }


 /**
  * The number of records in the CertExtension arrays.
  *
  * @access   public
  */
  public function getCertExtensionCount() {
    return ipworksencrypt_certmgr_get($this->handle, 23 );
  }
 /**
  * The number of records in the CertExtension arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertExtensionCount($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether or not the extension is defined as critical.
  *
  * @access   public
  */
  public function getCertExtensionCritical($certextensionindex) {
    return ipworksencrypt_certmgr_get($this->handle, 24 , $certextensionindex);
  }


 /**
  * The ASN.
  *
  * @access   public
  */
  public function getCertExtensionOID($certextensionindex) {
    return ipworksencrypt_certmgr_get($this->handle, 25 , $certextensionindex);
  }


 /**
  * The raw value of this certificate extension.
  *
  * @access   public
  */
  public function getCertExtensionValue($certextensionindex) {
    return ipworksencrypt_certmgr_get($this->handle, 26 , $certextensionindex);
  }


 /**
  * The certificate store to search for certificates.
  *
  * @access   public
  */
  public function getCertStore() {
    return ipworksencrypt_certmgr_get($this->handle, 27 );
  }
 /**
  * The certificate store to search for certificates.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStore($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password for the certificate store (if any).
  *
  * @access   public
  */
  public function getCertStorePassword() {
    return ipworksencrypt_certmgr_get($this->handle, 28 );
  }
 /**
  * The password for the certificate store (if any).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertStorePassword($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of certificate store for CertStore .
  *
  * @access   public
  */
  public function getCertStoreType() {
    return ipworksencrypt_certmgr_get($this->handle, 29 );
  }
 /**
  * The type of certificate store for CertStore .
  *
  * @access   public
  * @param    int   value
  */
  public function setCertStoreType($value) {
    $ret = ipworksencrypt_certmgr_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_certmgr_get_last_error($this->handle));
    }
    return $ret;
  }


  
 /**
  * Shows the certificate chain for the certificate (see the ShowCertificateChain method).
  *
  * @access   public
  * @param    array   Array of event parameters: certencoded, certsubject, certissuer, certserialnumber, truststatus, trustinfo    
  */
  public function fireCertChain($param) {
    return $param;
  }

 /**
  * Lists the certificates in a store (see the ListStoreCertificates method).
  *
  * @access   public
  * @param    array   Array of event parameters: certencoded, certsubject, certissuer, certserialnumber, hasprivatekey    
  */
  public function fireCertList($param) {
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
  * Lists the keysets in a CSP (see the ListKeys method).
  *
  * @access   public
  * @param    array   Array of event parameters: keycontainer, keytype, algid, keylen    
  */
  public function fireKeyList($param) {
    return $param;
  }

 /**
  * Lists the system certificate stores (see the ListCertificateStores and ListMachineStores methods).
  *
  * @access   public
  * @param    array   Array of event parameters: certstore    
  */
  public function fireStoreList($param) {
    return $param;
  }


}

?>
