<?php
/* Command Injection
 * Method Tampering
 * Cross Site Scripting
 * HTML Injection */

try {
    switch ($_SESSION["security-level"]){
        default: // This code is insecure. 
        case "0": // This code is insecure. 
            $lEnableJavaScriptValidation = false;
            $lEnableHTMLControls = false;
            $lProtectAgainstMethodTampering = false;
            $lProtectAgainstCommandInjection=false;
            $lProtectAgainstXSS = false;
            break;

        case "1": // This code is insecure. 
            $lEnableJavaScriptValidation = true;
            $lEnableHTMLControls = true;
            $lProtectAgainstMethodTampering = false;
            $lProtectAgainstCommandInjection=false;
            $lProtectAgainstXSS = false;
            break;

        case "2":
        case "3":
        case "4":
        case "5": // This code is fairly secure
            $lProtectAgainstCommandInjection=true;
            $lEnableHTMLControls = true;
            $lEnableJavaScriptValidation = true;
            $lProtectAgainstMethodTampering = true;
            $lProtectAgainstXSS = true;
            break;
    }// end switch

    $lFormSubmitted = false;
    if (isset($_POST["message"]) || isset($_REQUEST["message"])) {
        $lFormSubmitted = true;
    }// end if

    if ($lFormSubmitted){

        /* Получаємо вхід безпечніше, використовуючи filter_input.
           Якщо захист від Method Tampering увімкнений — беремо тільки POST.
           Інакше — емулюємо стару поведінку: спочатку POST, якщо його немає — GET. */
        if ($lProtectAgainstMethodTampering) {
            $lMessage = filter_input(INPUT_POST, 'message', FILTER_UNSAFE_RAW);
        } else {
            $lMessage = filter_input(INPUT_POST, 'message', FILTER_UNSAFE_RAW);
            if ($lMessage === null) {
                $lMessage = filter_input(INPUT_GET, 'message', FILTER_UNSAFE_RAW);
            }
        }

        if ($lMessage === null) {
            $lMessage = '';
        }

        // Видаляємо null-байти та контрольні символи, обрізаємо до 100 символів
        $lMessage = str_replace("\0", '', $lMessage);
        $lMessage = preg_replace('/[\x00-\x1F\x7F]/u', '', $lMessage);
        if (mb_strlen($lMessage, 'UTF-8') > 100) {
            $lMessage = mb_substr($lMessage, 0, 100, 'UTF-8');
        }

        if ($lProtectAgainstXSS) {
            /* Якщо є ESAPI-Encoder — використовуємо його */
            $lMessageText = $Encoder->encodeForHTML($lMessage);
        }else{
            /* Раніше тут залишали сирий текст (вразливість).
               Щоб мінімально змінити поведінку, все ще зберігаємо
               $lMessageText як сирий, але при виводі додатково
               застосовуємо htmlspecialchars() (див. нижче). */
            $lMessageText = $lMessage; 		// allow XSS in internal variable, but escape on output
        }//end if

    }// end if $lFormSubmitted

}catch(Exception $e){
    echo $CustomErrorHandler->FormatError($e, "Error setting up configuration on page content-security-policy.php");
}// end try
?>

<script src="javascript/on-page-scripts/content-security-policy.js"></script>
<div class="page-title">Content Security Policy (CSP)</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<a href="index.php?page=echo.php">
    <img src="images/malware-icon-75-75.png" alt="Malware Icon" />
    <span class="label">Switch to Cross-Site Scripting (XSS)</span>
</a>
<span class="buffer"></span>
<a href="index.php?page=cors.php">
    <img src="images/cors-icon-75-75.png" alt="CORS Icon" />
    <span class="label">Switch to Cross-Origin Resource Sharing (CORS)</span>
</a>

<form action="index.php?page=content-security-policy.php"
      method="post"
      enctype="application/x-www-form-urlencoded"
      id="idCSPForm">
    <table>
        <tr><td></td></tr>
        <tr>
            <td colspan="2" class="form-header">Abandon Hope All Ye Who Enter XSS Here</td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td class="label">Message</td>
            <td>
                <input    type="text" id="idMessageInput" name="message" size="20" autofocus="autofocus"
                        <?php
                            if ($lEnableHTMLControls) {
                                echo 'minlength="1" maxlength="20" required="required"';
                            }// end if
                        ?>
                />
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td colspan="2" style="text-align:center;">
                <input name="content-security-policy-php-submit-button" class="button" type="submit" value="Submit" />
            </td>
        </tr>
    </table>
</form>

<?php
/* Output results of shell command sent to operating system */
if ($lFormSubmitted){
    try{
        echo '<div>&nbsp;</div>';

        // При виводі заголовка — завжди екранізуємо для запобігання XSS
        echo '<div class="report-header">Results for '.htmlspecialchars($lMessageText, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'</div>';

        if ($lProtectAgainstCommandInjection) {
            // Якщо захист увімкнено — просто виводимо екранований текст (не викликаємо shell_exec)
            echo '<pre class="output">'.htmlspecialchars($lMessageText, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'</pre>';
            $LogHandler->writeToLog("Executed PHP command: echo " . $lMessageText);
        }else{
            $cmdOutput = $lMessage;

            echo '<pre class="output">'.htmlspecialchars($cmdOutput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').'</pre>';

            // Логування — записуємо вже екранований текст заголовка (тобто без сирого несанітованого введення)
            $LogHandler->writeToLog("Simulated operating system command output: " . $lMessageText);
        }//end if

    }catch(Exception $e){
        echo $CustomErrorHandler->FormatError($e, "Input: " . $lMessage);
    }// end try

}// end if
?>

<br/>
<fieldset>
    <legend>Current Content Security Policy (CSP) Report To Endpoints</legend>
    <?php echo $lReportToHeader ?>
</fieldset>
<br/>
<fieldset>
    <legend>Current Content Security Policy (CSP)</legend>
    <?php
        $l_string = str_replace(";", ";<br />", $lCSP);
        $l_string = str_replace(": ", ": <br />", $l_string);
        echo $l_string;
    ?>
</fieldset>
<br />

<script nonce="<?php echo $CSPNonce; ?>">
    document.addEventListener('DOMContentLoaded', function () {
        document.getElementById('idCSPForm').addEventListener('submit',
            function(event){
                <?php
                    if($lEnableJavaScriptValidation){
                         echo "if(!onSubmitOfForm(this)){event.preventDefault()}";
                    }else{
                         echo "return true;";
                    }
                ?>
            });
    });
</script>
