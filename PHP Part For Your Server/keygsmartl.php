<?php
/**
 * Created by Ebrahim Shafiei.
 * User: Windows
 * Date: 2016-03-26
 * Time: 8:23 PM
 */


require_once('keygsmartl/ipworksencrypt_aes.php');
require_once('keygsmartl/ipworksencrypt_rc2.php');
require_once('keygsmartl/ipworksencrypt_rc4.php');
require_once('keygsmartl/ipworksencrypt_ezcrypt.php');


// Start Time And Date Graber
$yearGraber = date("Y");
$monthGraber = date("m");
$dayGraber = date("d");
$hourGraber = date("h");
$minutesGraber = date("i");
$secondGraber = date("s");
// End Time And Date Graber

// Start Time Calculating
$sumForDateTime = $yearGraber + $monthGraber + $dayGraber + $hourGraber + $minutesGraber + $secondGraber;

$tokenCrypt = new IPWorksEncrypt_Ezcrypt();
$tokenCrypt->setAlgorithm(0); // 0 => AES
$tokenCrypt->setUseHex(TRUE);
$tokenCrypt->setInputMessage($sumForDateTime);
$tokenCrypt->setKeyPassword("nkw5L8ayqUYxXc4YHqNq9LUgyTDLtwfEKEN");
$tokenCrypt->doEncrypt();
$encryptedForClient = $tokenCrypt->getOutputMessage();


echo $encryptedForClient; // For User


?>


