<?php
/* Secure Conference Room Lookup
 * - Server-side enforcement of POST only (prevent method tampering)
 * - Whitelist validation for room common name
 * - Proper escaping for LDAP filters (ldap_escape when available)
 * - Safe output with htmlspecialchars
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/**
 * Safe ldap escape wrapper — uses ldap_escape if available, otherwise a minimal fallback.
 * We escape for LDAP filter context.
 */
function safe_ldap_escape(string $value): string {
    if (function_exists('ldap_escape')) {
        // LDAP_ESCAPE_FILTER mode escapes LDAP filter meta-chars
        return ldap_escape($value, '', LDAP_ESCAPE_FILTER);
    }
    // Fallback: escape the common filter metacharacters per RFC
    // Replace \ * ( ) NUL and slash of hex sequence
    $map = [
        '\\' => '\\5c',
        '*'  => '\\2a',
        '('  => '\\28',
        ')'  => '\\29',
        "\x00" => '\\00',
    ];
    return strtr($value, $map);
}

// Configuration defaults depending on "security-level" in session
$lEnableJavaScriptValidation = true;
$lEnableHTMLControls = true;
$lProtectAgainstMethodTampering = true;
$lProtectAgainstLDAPInjection = true;

// ensure session variable exists; default to secure mode if not set
$securityLevel = $_SESSION['security-level'] ?? '5';
switch ($securityLevel) {
    case "0":
    case "1":
        $lEnableJavaScriptValidation = ($securityLevel === "1");
        $lEnableHTMLControls = ($securityLevel === "1");
        $lProtectAgainstMethodTampering = false;
        $lProtectAgainstLDAPInjection = false;
        break;
    default:
        // levels 2-5 (secure)
        $lProtectAgainstMethodTampering = true;
        $lProtectAgainstLDAPInjection = true;
        $lEnableHTMLControls = true;
        $lEnableJavaScriptValidation = true;
        break;
}

$lFormSubmitted = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['default_room_common_name'])) {
    $lFormSubmitted = true;
}

$lRoomCommonNameText = '';
if ($lFormSubmitted) {
    // Enforce POST-only if protecting against method tampering
    if ($lProtectAgainstMethodTampering && $_SERVER['REQUEST_METHOD'] !== 'POST') {
        // reject silently or show error
        http_response_code(405);
        echo '<div class="error-message">Invalid request method.</div>';
        exit;
    }

    // Get raw input from POST (do not use $_REQUEST)
    $rawRoomCN = $_POST['default_room_common_name'] ?? '';

    // Server-side whitelist validation:
    // Example policy: allow letters, digits, hyphen, underscore, max length 20
    // Adjust the regex/policy to match your real room naming rules.
    $maxLen = 20;
    $allowedPattern = '/^[A-Za-z0-9_\-]{1,' . $maxLen . '}$/';

    if (!preg_match($allowedPattern, $rawRoomCN)) {
        // Invalid input — do not include raw value in any LDAP filter or logs
        echo '<div class="error-message">Invalid room identifier provided.</div>';
        // optional: write safe log entry
        if (isset($LogHandler)) {
            $LogHandler->writeToLog('Rejected invalid room identifier input.');
        }
        // Stop processing
        $lFormSubmitted = false;
    } else {
        // Safe: escape for LDAP filter usage
        if ($lProtectAgainstLDAPInjection) {
            $lRoomCommonNameText = safe_ldap_escape($rawRoomCN);
        } else {
            // insecure mode (for testing only)
            $lRoomCommonNameText = $rawRoomCN;
        }
    }
}

// --- HTML form / client-side checks (kept, but server already enforces) ---
?>
<div class="page-title">Conference Room Lookup</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<script type="text/javascript">
var onSubmitOfForm = function(theForm){
    <?php if($lEnableJavaScriptValidation){ ?>
        var lOSLDAPInjectionPattern = /[;&\*\\()]/;
        var lCrossSiteScriptingPattern = /[<>=]/;
    <?php } else { ?>
        var lOSLDAPInjectionPattern = /[]/;
        var lCrossSiteScriptingPattern = /[]/;
    <?php } ?>

    if (theForm.default_room_common_name.value.search(lOSLDAPInjectionPattern) > -1) {
        alert("Malicious characters are not allowed.");
        return false;
    } else if (theForm.default_room_common_name.value.search(lCrossSiteScriptingPattern) > -1) {
        alert("Characters used in cross-site scripting are not allowed.");
        return false;
    }
    return true;
};
</script>

<form action="index.php?page=conference-room-lookup.php"
      method="post"
      enctype="application/x-www-form-urlencoded"
      onsubmit="return onSubmitOfForm(this);"
      id="idConferenceRoomLookupForm">
    <table>
        <tr id="id-bad-cred-tr" style="display: none;">
            <td colspan="2" class="error-message">Error: Invalid Input</td>
        </tr>
        <tr><td></td></tr>
        <tr><td class="form-header">Available Conference Room Lookup</td></tr>
        <tr><td></td></tr>
        <tr>
            <td>
                <input type="hidden" id="idDefaultRoomCommonNameInput" name="default_room_common_name" value="1F104"
                    <?php if ($lEnableHTMLControls) { echo 'minlength="1" maxlength="20" required="required"'; } ?> />
            </td>
        </tr>
        <tr><td></td></tr>
        <tr>
            <td style="text-align:center;">
                <input name="conference-lookup-php-submit-button" class="button" type="submit" value="Find Available Rooms" />
            </td>
        </tr>
        <tr><td></td></tr>
    </table>
</form>

<?php
/* Output results of LDAP search (only if server-side validation passed) */
if ($lFormSubmitted && $lRoomCommonNameText !== '') {
    try {
        require_once __SITE_ROOT__.'/includes/ldap-config.inc';

        $ldapconn = ldap_connect("ldap://" . LDAP_HOST . ":" . LDAP_PORT);
        if ($ldapconn === false) {
            throw new Exception('Could not connect to LDAP server.');
        }
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);

        $bind = @ldap_bind($ldapconn, LDAP_BIND_DN, LDAP_BIND_PASSWORD);
        if ($bind === false) {
            throw new Exception('LDAP bind failed.');
        }

        // Build filter using escaped value. We already escaped $lRoomCommonNameText for filter context.
        $filter = sprintf('(|(cn=2F204)(cn=%s))', $lRoomCommonNameText);

        $sr = @ldap_search($ldapconn, LDAP_BASE_DN, $filter);
        if ($sr === false) {
            throw new Exception('LDAP search failed.');
        }

        $entries = ldap_get_entries($ldapconn, $sr);

        echo '<table><tr><th>These rooms are available</th></tr>';
        // ldap_get_entries returns an array with "count" and numeric indices 0..count-1
        $count = isset($entries['count']) ? (int)$entries['count'] : 0;
        for ($i = 0; $i < $count; $i++) {
            if (isset($entries[$i]['cn'][0])) {
                echo '<tr><td>' . htmlspecialchars($entries[$i]['cn'][0], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</td></tr>';
            }
        }
        echo '</table>';

        if (isset($LogHandler)) {
            // Log the escaped (not raw) input and avoid logging raw user input
            $LogHandler->writeToLog("Executed LDAP search on (escaped): " . $lRoomCommonNameText);
        }

        ldap_free_result($sr);
        ldap_unbind($ldapconn);
    } catch (Exception $e) {
        // Use your custom error handling routine if available; otherwise show generic message
        if (isset($CustomErrorHandler) && method_exists($CustomErrorHandler, 'FormatError')) {
            echo $CustomErrorHandler->FormatError($e, "Input: (escaped) " . $lRoomCommonNameText);
        } else {
            // Avoid revealing internal error details in production
            echo '<div class="error-message">An error occurred while processing your request.</div>';
            error_log('Conference lookup error: ' . $e->getMessage());
        }
    }
}
?>
