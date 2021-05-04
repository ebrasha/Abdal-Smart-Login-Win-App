<?php
/**
 * Created by Ebrahim Shafiei.
 * User: Windows
 * Date: 2016-03-31
 * Time: 1:29 AM
 */

function ioef($enCryptStr)
{
    $charArr = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z");
    $enCryptStrToHex = bin2hex($enCryptStr);
    $enCryptStrToBase64 = base64_encode($enCryptStrToHex);
    $enCryptStrToMD5 = md5($enCryptStrToBase64);
    $enCryptStrReplace = str_ireplace($charArr, "", $enCryptStrToMD5, $i);
}

?>
