<?php
    /* Known Vulnerabilities
     * SQL Injection, (Fix: Use Schematized Stored Procedures)
     * Cross Site Scripting, (Fix: Encode all output)
     * Cross Site Request Forgery, (Fix: Tokenize transactions)
     * Insecure Direct Object Reference, (Fix: Tokenize Object References)
     * Denial of Service, (Fix: Truncate Log Queries)
     * Loading of Local Files, (Fix: Tokenize Object Reference - Filename references in this case)
     * Improper Error Handling, (Fix: Employ custom error handler)
     * SQL Exception, (Fix: Employ custom error handler)
     * HTTP Parameter Pollution (Fix: Scope request variables)
     * Method Tampering
     */

    try {
        switch ($_SESSION["security-level"]){
            default:
            case "0": // insecure
                $lEnableHTMLControls = false;
                $lUseTokenization = false;
                $lEncodeOutput = false;
                $lProtectAgainstMethodTampering = false;
            break;

            case "1": // insecure
                $lEnableHTMLControls = true;
                $lUseTokenization = false;
                $lEncodeOutput = false;
                $lProtectAgainstMethodTampering = false;
            break;

            case "2":
            case "3":
            case "4":
            case "5": // secure
                $lEnableHTMLControls = true;
                $lUseTokenization = true;
                $lEncodeOutput = true;
                $lProtectAgainstMethodTampering = true;
            break;
        }

        if ($lEnableHTMLControls) {
            $lHTMLControlAttributes='required="required"';
        }else{
            $lHTMLControlAttributes="";
        }

    }catch(Exception $e){
        echo $CustomErrorHandler->FormatError($e, "Error in text file viewer. Cannot load file.");
    }
?>

<div class="page-title">Hacker Files of Old</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<form action="index.php?page=text-file-viewer.php"
      method="post"
      enctype="application/x-www-form-urlencoded">

    <table>
        <tr id="id-bad-cred-tr" style="display: none;">
            <td colspan="2" class="error-message">
                Validation Error: Bad Selection
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td colspan="2" class="form-header">
                Take the time to read some of these great old school hacker text files.<br />
                Just choose one from the list and submit.
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td class="label">Text File Name</td>
            <td>
                <select size="1" name="textfile" id="id_textfile_select" autofocus="autofocus" <?php echo $lHTMLControlAttributes ?>>

                    <option value="<?php echo $lUseTokenization ? 1 : 'auditool.txt'; ?>">
                        Intrusion Detection in Computers by Victor H. Marshall (1991)
                    </option>
                    <option value="<?php echo $lUseTokenization ? 2 : 'atms'; ?>">
                        Overview of ATMs and Encoding System
                    </option>
                    <option value="<?php echo $lUseTokenization ? 3 : 'backdoor.txt'; ?>">
                        How to Hold Onto UNIX Root
                    </option>
                    <option value="<?php echo $lUseTokenization ? 4 : 'hack1.hac'; ?>">
                        The Basics of Hacking
                    </option>
                    <option value="<?php echo $lUseTokenization ? 5 : 'hacking101.hac'; ?>">
                        HACKING 101 — Johnny Rotten
                    </option>

                </select>
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td colspan="2" style="text-align:center;">
                <input name="text-file-viewer-php-submit-button" class="button" type="submit" value="View File" />
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td class="label" colspan="2">
                For other great texts, check out
                <a href="http://www.textfiles.com/" target="_blank">
                    http://www.textfiles.com/
                </a>.
            </td>
        </tr>
        <tr><td>&nbsp;</td></tr>
    </table>
</form>


<?php
try {
    if (isset($_POST['text-file-viewer-php-submit-button'])){

        // Protection from method tampering
        if ($lProtectAgainstMethodTampering){
            $pTextFile = $_POST["textfile"];
        } else {
            $pTextFile = $_REQUEST['textfile'];
        }

        // White list of allowed files locally stored
        // This removes ANY possibility of Path Traversal
        $allowedFiles = array(
            1 => "auditool.txt",
            2 => "atms",
            3 => "backdoor.txt",
            4 => "hack1.hac",
            5 => "hacking101.hac"
        );

        $baseDirectory = __DIR__ . "/textfiles/";

        if ($lUseTokenization){
            // Token → file name
            if (!preg_match("/^[0-9]+$/", $pTextFile) || !isset($allowedFiles[$pTextFile])) {
                throw new Exception("Invalid input token. Access denied.");
            }

            $lURL = $baseDirectory . $allowedFiles[$pTextFile];

        } else {
            // NON-tokenized request must ALSO pass strict whitelist
            if (!in_array($pTextFile, $allowedFiles)) {
                throw new Exception("Invalid filename. Access denied.");
            }

            $lURL = $baseDirectory . $pTextFile;
        }

        // Ensure resolved path is INSIDE the directory (final anti-PathTraversal)
        $real = realpath($lURL);
        if ($real === false || strpos($real, realpath($baseDirectory)) !== 0){
            throw new Exception("Access denied – invalid resolved path.");
        }

        // Encode display name if needed
        if ($lEncodeOutput){
            $lTextFileDescription = $Encoder->encodeForHTML($lURL);
        } else {
            $lTextFileDescription = $lURL;
        }

        // Log usage
        try {
            $LogHandler->writeToLog("Using file: " . $lTextFileDescription);
        } catch (Exception $e) { }

        // Open file securely
        try{
            $handle = @fopen($real, "r");
            if ($handle === false) {
                throw new Exception("Error opening file.");
            }

            echo '<span class="label">File: '.$lTextFileDescription.'</span>';
            echo '<pre>';

            while (!feof($handle)) {
                $chunk = fgets($handle, 8192);
                if ($chunk === false) break;
                echo htmlspecialchars($chunk, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            }
            echo '</pre>';
            fclose($handle);

            try {
                $LogHandler->writeToLog("Displayed file: " . $lTextFileDescription);
            } catch (Exception $e) { }

        }catch(Exception $e){
            echo $CustomErrorHandler->FormatError($e, "Error opening file stream.");
        }

    }
}catch(Exception $e){
    echo $CustomErrorHandler->FormatError($e, "Error in text file viewer.");
}
?>
