<?php

require_once('ipworksencrypt_keys.php');

/**
 * IP*Works! Encrypt V9 PHP Edition - DPAPI Component
 *
 * Copyright (c) 2016 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class IPWorksEncrypt_DPAPI {
  
  var $handle;

  public function __construct() {
    $this->handle = ipworksencrypt_dpapi_open(IPWORKSENCRYPT_OEMKEY_77);
    ipworksencrypt_dpapi_register_callback($this->handle, 1, array($this, 'fireError'));
    ipworksencrypt_dpapi_register_callback($this->handle, 2, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    ipworksencrypt_dpapi_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return ipworksencrypt_dpapi_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return ipworksencrypt_dpapi_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting .
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = ipworksencrypt_dpapi_do_config($this->handle, $configurationstring);
		$err = ipworksencrypt_dpapi_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Protects the data.
  *
  * @access   public
  */
  public function doProtect() {
    $ret = ipworksencrypt_dpapi_do_protect($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the component.
  *
  * @access   public
  */
  public function doReset() {
    $ret = ipworksencrypt_dpapi_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Unprotects the data.
  *
  * @access   public
  */
  public function doUnprotect() {
    $ret = ipworksencrypt_dpapi_do_unprotect($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return ipworksencrypt_dpapi_get($this->handle, 0);
  }
 /**
  * The description of data.
  *
  * @access   public
  */
  public function getDataDescription() {
    return ipworksencrypt_dpapi_get($this->handle, 1 );
  }
 /**
  * The description of data.
  *
  * @access   public
  * @param    string   value
  */
  public function setDataDescription($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The file to process.
  *
  * @access   public
  */
  public function getInputFile() {
    return ipworksencrypt_dpapi_get($this->handle, 2 );
  }
 /**
  * The file to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The message to process.
  *
  * @access   public
  */
  public function getInputMessage() {
    return ipworksencrypt_dpapi_get($this->handle, 3 );
  }
 /**
  * The message to process.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputMessage($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output file.
  *
  * @access   public
  */
  public function getOutputFile() {
    return ipworksencrypt_dpapi_get($this->handle, 4 );
  }
 /**
  * The output file.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The output message after processing.
  *
  * @access   public
  */
  public function getOutputMessage() {
    return ipworksencrypt_dpapi_get($this->handle, 5 );
  }


 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  */
  public function getOverwrite() {
    return ipworksencrypt_dpapi_get($this->handle, 6 );
  }
 /**
  * Indicates whether or not the component should overwrite files.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOverwrite($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An optional password to further protect data.
  *
  * @access   public
  */
  public function getPassword() {
    return ipworksencrypt_dpapi_get($this->handle, 7 );
  }
 /**
  * An optional password to further protect data.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The title of the prompt window.
  *
  * @access   public
  */
  public function getPromptTitle() {
    return ipworksencrypt_dpapi_get($this->handle, 8 );
  }
 /**
  * The title of the prompt window.
  *
  * @access   public
  * @param    string   value
  */
  public function setPromptTitle($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to display a prompt.
  *
  * @access   public
  */
  public function getPromptUser() {
    return ipworksencrypt_dpapi_get($this->handle, 9 );
  }
 /**
  * Whether to display a prompt.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setPromptUser($value) {
    $ret = ipworksencrypt_dpapi_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . ipworksencrypt_dpapi_get_last_error($this->handle));
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
