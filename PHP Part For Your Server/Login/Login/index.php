<?php
/**
 * Created by Ebrahim Shafiei.
 * User: Hackers.Zone
 * Date: 2016-08-21
 * Time: 1:28 AM
 */


require_once('../keygsmartl/ipworksencrypt_aes.php');
require_once('../keygsmartl/ipworksencrypt_rc2.php');
require_once('../keygsmartl/ipworksencrypt_rc4.php');
require_once('../keygsmartl/ipworksencrypt_ezcrypt.php');


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

if ($_SERVER['REQUEST_METHOD'] == "POST") {

    $userToken = $_POST["tokenKey"];
    $tokenDecrypt = new IPWorksEncrypt_Ezcrypt();
    $tokenDecrypt->setAlgorithm(6); // 6 => RC4
    $tokenDecrypt->setUseHex(TRUE);
    $tokenDecrypt->setInputMessage($userToken);
    $tokenDecrypt->setKeyPassword("Pku78TPybuzCnGvRUy074Bawk6O5MR4nWSq");
    $tokenDecrypt->doDecrypt();
    $decryptedForCheckValidToken = $tokenDecrypt->getOutputMessage();

    $loginAccessAllow = false;  // Default Value For More Security


    for ($i = 1; $i <= 20; $i++) {
        $decryptedForCheckValidToken++;
        if ($decryptedForCheckValidToken == $sumForDateTime) {
            $loginAccessAllow = true;
            break;
        } else {
            $loginAccessAllow = false;
        }

    } // End For Loop
    
} // End If (Post Method Checking)


?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Abdal Smart Login - Sample</title>
    <link rel="stylesheet" href="css/bootstrap.css"/>
    <link rel="stylesheet" href="css/custom.css"/>
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-md-1"></div>
        <div class="col-md-10">
            <form class="form" action="index.php" method="post">
                <div class="form-group">
                    <br/>
                    <br/>
                    <label for="tokenKey">Token : </label>
                    <input type="text" name="tokenKey" class="form-control" id="tokenKey" placeholder="Type The Token"/>
                </div>
                <button type="submit" class="btn btn-primary">Security Check</button>
            </form>
            <br/>
            <br/>
            <?php if ($_SERVER['REQUEST_METHOD'] == "POST") {
                if ($loginAccessAllow == true) {

                    echo "<div class='alert alert-success'>Your Toke Is Valid</div>";
                } else {
                    echo "<div class='alert alert-danger'>Your Toke Is Not Valid</div>";
                }
            }
            ?>

        </div>
        <div class="col-md-1"></div>
    </div>
</div>

<script src="js/bootstrap.js"></script>
<script src="js/jquery.js"></script>
</body>
</html>
