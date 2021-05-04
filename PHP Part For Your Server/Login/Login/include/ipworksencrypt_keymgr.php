<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - KeyMgr Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_KeyMgr {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_keymgr_open(IPWORKSENCRYPT_OEMKEY_10);
    ipworksencrypt_keymgr_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_keymgr_register_callback($this->handle, 2, array($this, 'fireKeyList'));
    ipworksencrypt_keymgr_register_callback($this->handle, 3, array($this, 'fireKeyPassphrase'));
    ipworksencrypt_keymgr_register_callback($this->handle, 4, array($this, 'fireSignatureList'));
    ipworksencrypt_keymgr_register_callback($this->handle, 5, array($this, 'fireStatus'));
    ipworksencrypt_keymgr_register_callback($this->handle, 6, array($this, 'fireSubkeyList'));
  }
  
  public function __destruct() {
    ipworksencrypt_keymgr_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_keymgr_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_keymgr_get_last_error_code($this->handle);
  }

 /**
  * Adds a designated revoker to the key.
  *
  * @access   public
  * @param    string    userid
  */
  public function doAddRevoker($userid) {
    $ret = ipworksencrypt_keymgr_do_addrevoker($this->handle, $userid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds the specified user Id to the current key.
  *
  * @access   public
  * @param    string    userid
  */
  public function doAddUserId($userid) {
    $ret = ipworksencrypt_keymgr_do_adduserid($this->handle, $userid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Changes the expiration date of the key.
  *
  * @access   public
  * @param    int    expirationdate
  */
  public function doChangeExpirationDate($expirationdate) {
    $ret = ipworksencrypt_keymgr_do_changeexpirationdate($this->handle, $expirationdate);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Changes the passphrase of the current key.
  *
  * @access   public
  * @param    string    passphrase
  */
  public function doChangePassphrase($passphrase) {
    $ret = ipworksencrypt_keymgr_do_changepassphrase($this->handle, $passphrase);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
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
    $ret = ipworksencrypt_keymgr_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_keymgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates an OpenPGP key pair.
  *
  * @access   public
  * @param    string    userid
  * @param    string    passphrase
  */
  public function doCreateKey($userid, $passphrase) {
    $ret = ipworksencrypt_keymgr_do_createkey($this->handle, $userid, $passphrase);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Deletes the specified key.
  *
  * @access   public
  * @param    string    userid
  */
  public function doDeleteKey($userid) {
    $ret = ipworksencrypt_keymgr_do_deletekey($this->handle, $userid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the public key of the current key.
  *
  * @access   public
  * @param    string    filename
  * @param    boolean    useasciiarmor
  */
  public function doExportPublicKey($filename, $useasciiarmor) {
    $ret = ipworksencrypt_keymgr_do_exportpublickey($this->handle, $filename, $useasciiarmor);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the private key of the current key.
  *
  * @access   public
  * @param    string    filename
  * @param    boolean    useasciiarmor
  */
  public function doExportSecretKey($filename, $useasciiarmor) {
    $ret = ipworksencrypt_keymgr_do_exportsecretkey($this->handle, $filename, $useasciiarmor);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Imports the key specified by UserId to the current keyring.
  *
  * @access   public
  * @param    string    filename
  * @param    string    userid
  */
  public function doImportKey($filename, $userid) {
    $ret = ipworksencrypt_keymgr_do_importkey($this->handle, $filename, $userid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Imports the key specified by UserId to the current keyring.
  *
  * @access   public
  * @param    string    data
  * @param    string    userid
  */
  public function doImportKeyB($data, $userid) {
    $ret = ipworksencrypt_keymgr_do_importkeyb($this->handle, $data, $userid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Lists keys in the specified Keyring .
  *
  * @access   public
  */
  public function doListKeys() {
    $ret = ipworksencrypt_keymgr_do_listkeys($this->handle);
		$err = ipworksencrypt_keymgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Lists all signatures of the current key.
  *
  * @access   public
  */
  public function doListSignatures() {
    $ret = ipworksencrypt_keymgr_do_listsignatures($this->handle);
		$err = ipworksencrypt_keymgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Lists the subkeys of the currently selected key.
  *
  * @access   public
  */
  public function doListSubkeys() {
    $ret = ipworksencrypt_keymgr_do_listsubkeys($this->handle);
		$err = ipworksencrypt_keymgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads the keyring from disk.
  *
  * @access   public
  * @param    string    keyringpath
  */
  public function doLoadKeyring($keyringpath) {
    $ret = ipworksencrypt_keymgr_do_loadkeyring($this->handle, $keyringpath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component properties.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_keymgr_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Revokes the specified key.
  *
  * @access   public
  * @param    string    keyid
  */
  public function doRevokeKey($keyid) {
    $ret = ipworksencrypt_keymgr_do_revokekey($this->handle, $keyid);
		$err = ipworksencrypt_keymgr_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the current Keyring to disk.
  *
  * @access   public
  * @param    string    keyringpath
  */
  public function doSaveKeyring($keyringpath) {
    $ret = ipworksencrypt_keymgr_do_savekeyring($this->handle, $keyringpath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs the specified user Id of the current key.
  *
  * @access   public
  * @param    string    userid
  * @param    string    issueruserid
  */
  public function doSignUserId($userid, $issueruserid) {
    $ret = ipworksencrypt_keymgr_do_signuserid($this->handle, $userid, $issueruserid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies the passphrase of specified key.
  *
  * @access   public
  * @param    string    passphrase
  */
  public function doVerifyPassphrase($passphrase) {
    $ret = ipworksencrypt_keymgr_do_verifypassphrase($this->handle, $passphrase);

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_keymgr_get($this->handle, 0);
  }
 /**
  * The date when this key becomes valid.
  *
  * @access   public
  */
  public function getKeyEffectiveDate() {
    return ipworksencrypt_keymgr_get($this->handle, 1 );
  }


 /**
  * The key.
  *
  * @access   public
  */
  public function getKeyEncoded() {
    return ipworksencrypt_keymgr_get($this->handle, 2 );
  }
 /**
  * The key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyEncoded($value) {
    $ret = ipworksencrypt_keymgr_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The date the key expires.
  *
  * @access   public
  */
  public function getKeyExpirationDate() {
    return ipworksencrypt_keymgr_get($this->handle, 3 );
  }


 /**
  * The hex-encoded, 20-byte fingerprint of the key.
  *
  * @access   public
  */
  public function getKeyFingerprint() {
    return ipworksencrypt_keymgr_get($this->handle, 4 );
  }


 /**
  * The hex-encoded, 4-byte key Id.
  *
  * @access   public
  */
  public function getKeyId() {
    return ipworksencrypt_keymgr_get($this->handle, 5 );
  }


 /**
  * If the specified key has alternate user Ids associated with it, this property returns a comma-separated list of the other user Ids.
  *
  * @access   public
  */
  public function getKeyOtherUserIds() {
    return ipworksencrypt_keymgr_get($this->handle, 6 );
  }


 /**
  * The passphrase for the key's secret key (if any).
  *
  * @access   public
  */
  public function getKeyPassphrase() {
    return ipworksencrypt_keymgr_get($this->handle, 7 );
  }
 /**
  * The passphrase for the key's secret key (if any).
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyPassphrase($value) {
    $ret = ipworksencrypt_keymgr_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The public key of the key.
  *
  * @access   public
  */
  public function getKeyPublicKey() {
    return ipworksencrypt_keymgr_get($this->handle, 8 );
  }


 /**
  * A text description of the public key algorithm of the  key.
  *
  * @access   public
  */
  public function getKeyPublicKeyAlgorithm() {
    return ipworksencrypt_keymgr_get($this->handle, 9 );
  }


 /**
  * The length of the public key in bits.
  *
  * @access   public
  */
  public function getKeyPublicKeyLength() {
    return ipworksencrypt_keymgr_get($this->handle, 10 );
  }


 /**
  * Whether or not the key is revoked.
  *
  * @access   public
  */
  public function getKeyRevoked() {
    return ipworksencrypt_keymgr_get($this->handle, 11 );
  }


 /**
  * The secret key of the key (if available).
  *
  * @access   public
  */
  public function getKeySecretKey() {
    return ipworksencrypt_keymgr_get($this->handle, 12 );
  }


 /**
  * Whether or not a secret key is available for the selected key.
  *
  * @access   public
  */
  public function getKeySecretKeyAvailable() {
    return ipworksencrypt_keymgr_get($this->handle, 13 );
  }


 /**
  * A text description of UsageFlags .
  *
  * @access   public
  */
  public function getKeyUsage() {
    return ipworksencrypt_keymgr_get($this->handle, 14 );
  }


 /**
  * Flags that show the intended use for the key.
  *
  * @access   public
  */
  public function getKeyUsageFlags() {
    return ipworksencrypt_keymgr_get($this->handle, 15 );
  }


 /**
  * The user Id of the key.
  *
  * @access   public
  */
  public function getKeyUserId() {
    return ipworksencrypt_keymgr_get($this->handle, 16 );
  }
 /**
  * The user Id of the key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyUserId($value) {
    $ret = ipworksencrypt_keymgr_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_keymgr_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The location on disk of the keyring.
  *
  * @access   public
  */
  public function getKeyring() {
    return ipworksencrypt_keymgr_get($this->handle, 17 );
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
  * Fires for each key in the keyring when ListKeys is called.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, keyid, fingerprint, hassecretkey, publickeyalgorithm, publickeylength    
  */
  public function fireKeyList($param) {
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
  * Fires for each signature of the current key when ListSignatures is called.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, issuerkeyid, issueruserid, publickeyalgorithm, hashalgorithm, effectivedate, signatureclass, validitystatus    
  */
  public function fireSignatureList($param) {
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
  * Fires once for each subkey listed when ListSubkeys is called.
  *
  * @access   public
  * @param    array   Array of event parameters: keyid, fingerprint, publickeyalgorithm, publickeylength, usageflags, usage, effectivedate, expirationdate, revoked    
  */
  public function fireSubkeyList($param) {
    return $param;
  }


}

?>
