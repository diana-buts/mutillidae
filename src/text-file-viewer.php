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
   			case "0": // This code is insecure
				$lEnableHTMLControls = false;
   				$lUseTokenization = false;
				$lEncodeOutput = false;
				$lProtectAgainstMethodTampering = false;
			break;

   			case "1": // This code is insecure
				$lEnableHTMLControls = true;
   				$lUseTokenization = false;
				$lEncodeOutput = false;
				$lProtectAgainstMethodTampering = false;
			break;

			case "2":
			case "3":
			case "4":
	   		case "5": // This code is fairly secure
				$lEnableHTMLControls = true;
	   			$lUseTokenization = true;
				$lEncodeOutput = true;
				$lProtectAgainstMethodTampering = true;
			break;
	   	}// end switch ($_SESSION["security-level"])

	   	if ($lEnableHTMLControls) {
	   		$lHTMLControlAttributes='required="required"';
	   	}else{
	   		$lHTMLControlAttributes="";
	   	}// end if

	}catch(Exception $e){
		echo $CustomErrorHandler->FormatError($e, "Error in text file viewer. Cannot load file.");
	}// end try
?>

<div class="page-title">Hacker Files of Old</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<form 	action="index.php?page=text-file-viewer.php" 
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
			<td colspan="2" class="form-header">Take the time to read some of these great old school hacker text files.<br />Just choose one form the list and submit.</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td class="label">Text File Name</td>
			<td>
				<select size="1" name="textfile" id="id_textfile_select" autofocus="autofocus" <?php echo $lHTMLControlAttributes ?>>
					<option value="<?php if ($lUseTokenization){echo 1;}else{echo 'http://www.textfiles.com/hacking/auditool.txt';}?>">Intrusion Detection in Computers by Victor H. Marshall (January 29, 1991)</option>
					<option value="<?php if ($lUseTokenization){echo 2;}else{echo 'http://www.textfiles.com/hacking/atms';}?>">An Overview of ATMs and Information on the Encoding System</option>
					<option value="<?php if ($lUseTokenization){echo 3;}else{echo 'http://www.textfiles.com/hacking/backdoor.txt';}?>">How to Hold Onto UNIX Root Once You Have It</option>
					<option value="<?php if ($lUseTokenization){echo 4;}else{echo 'http://www.textfiles.com/hacking/hack1.hac';}?>">The Basics of Hacking, by the Knights of Shadow (Intro)</option>
					<option value="<?php if ($lUseTokenization){echo 5;}else{echo 'http://www.textfiles.com/hacking/hacking101.hac';}?>">HACKING 101 - By Johnny Rotten - Course #1 - Hacking, Telenet, Life</option>
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
			<td class="label" colspan="2">For other great old school hacking texts, check out 
			<a href="http://www.textfiles.com/" target="_blank">
				http://www.textfiles.com/
			</a>.</td></tr>
			<tr>
			<td>&nbsp;</td>
		</tr>
	</table>
</form>

<?php
	try {
		if (isset($_POST['text-file-viewer-php-submit-button'])){

			/********************************************
			 * Protect against Method Tampering in security level 5
			 *********************************************/
			if ($lProtectAgainstMethodTampering){
				$pTextFile=$_POST["textfile"];
			}else{
				/* insecure: $_REQUEST would take input from GET or POST. 
				 * This can result in an HTTP Parameter Polution
	   			 * attack. If a site uses POST, then grab input from _POST. Use _GET for gets. HPP can
	   			 * occur more easily when input is ambiguous.
	   			 */
				$pTextFile = $_REQUEST['textfile'];
			}//end if

			/********************************************
			 * Protect against IDOR in security level 5
			 *********************************************/
			$lURL = "";
			if ($lUseTokenization) {
		   			/* mapping: tokens -> URLs (safe) */
		   			/* Validate token strictly: must be integer token */
		   			$isDigits = (preg_match("/^\d{1,2}$/", $pTextFile) == 1);
		   			if ($isDigits && $pTextFile > 0 && $pTextFile < 11){
		   				switch($pTextFile){
							default:
		   					case 1: $lURL = "http://www.textfiles.com/hacking/auditool.txt";break;
		   					case 2: $lURL = "http://www.textfiles.com/hacking/atms";break;
		   					case 3: $lURL = "http://www.textfiles.com/hacking/backdoor.txt";break;
		   					case 4: $lURL = "http://www.textfiles.com/hacking/hack1.hac";break;
		   					case 5: $lURL = "http://www.textfiles.com/hacking/hacking101.hac";break;
		   				}// end switch($pTextFile)
		   			}else{
		   				throw(new Exception("Expected integer input. Cannot process request. Support team alerted."));
		   			}// end if
			} else {
				/* When not using tokenization, very strict validation is required:
				   - must be a valid URL
				   - scheme must be http or https
				   - hostname must be textfiles.com or a subdomain of textfiles.com
				   This prevents path traversal, file://, local file access, etc.
				*/
				$lURL = $pTextFile;

				// validate as URL
				if (!filter_var($lURL, FILTER_VALIDATE_URL)) {
					throw(new Exception("Invalid URL provided. Cannot process request."));
				}

				$parts = parse_url($lURL);
				if ($parts === false || !isset($parts['scheme']) || !isset($parts['host'])) {
					throw(new Exception("Invalid URL structure. Cannot process request."));
				}

				$scheme = strtolower($parts['scheme']);
				if (!in_array($scheme, array('http', 'https'))) {
					// disallow file://, ftp://, data://, etc.
					throw(new Exception("Only HTTP/HTTPS URLs are permitted."));
				}

				$host = strtolower($parts['host']);
				// allow only textfiles.com (including subdomains)
				if (!preg_match('/(^|\.)textfiles\.com$/', $host)) {
					throw(new Exception("External hosts are not permitted."));
				}

				// prevent userinfo in URL (e.g. user:pass@host)
				if (isset($parts['user']) || isset($parts['pass'])) {
					throw(new Exception("Credentials in URL are not permitted."));
				}

				// optional: disallow query fragments that could be used in some attacks (keep conservative)
				// (leave path and query as-is for legitimate reads)

				// At this point $lURL is considered safe for reading from the allowed domain only.
			}// end if $lUseTokenization

			/********************************************
			 * Protect against XSS in security level 5
			 *********************************************/
			if ($lEncodeOutput){
				$lTextFileDescription = $Encoder->encodeForHTML($lURL);
			} else {
				$lTextFileDescription = $lURL;
			}// end if $lEncodeOutput

			/********************************************
			 * Log file description
			 *********************************************/
			try {
				$LogHandler->writeToLog("Using URL: " . $lTextFileDescription . " based on user choice.");
			} catch (Exception $e) {
				//Do nothing. Do not interrupt page for failed log attempt.
			}//end try

			/********************************************
			 * Open file and display contents
			 *********************************************/
			try{
			    // open file handle
				$handle = @fopen($lURL, "r");
				if ($handle === false) {
					throw(new Exception("Error opening remote resource. Cannot load file."));
				}

	   			echo '<span class="label">File: '.$lTextFileDescription.'</span>';
	   			echo '<pre>';
	   			// read in safe chunks to avoid memory issues on very large files
	   			while (!feof($handle)) {
	   				$chunk = fgets($handle, 8192);
	   				if ($chunk === false) {
	   					// break on read error or EOF
	   					break;
	   				}
	   				echo htmlspecialchars($chunk, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	   			}
				echo '</pre>';
				fclose($handle);

				try {
					$LogHandler->writeToLog("Displayed contents of URL: " . $lTextFileDescription);
				} catch (Exception $e) {
					//Do nothing. Do not interrupt page for failed log attempt.
				}//end try

			}catch(Exception $e){
				echo $CustomErrorHandler->FormatError($e, "Error opening file stream. Cannot load file.");
			}// end try

		}// end if (isset($_POST['text-file-viewer-php-submit-button']))
	}catch(Exception $e){
		echo $CustomErrorHandler->FormatError($e, "Error in text file viewer. Cannot load file.");
	}// end try
?>
