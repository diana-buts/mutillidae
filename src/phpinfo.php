<div class="page-title">Secret PHP Server Configuration Page</div>

<?php
    // Default: do NOT show sensitive system information
    $lShowAdminPage = false;

    // Determine security level
    $lSecurityLevel = $_SESSION["security-level"] ?? 0;

    switch ($lSecurityLevel) {
        case "0":
        case "1":
            // Even in insecure mode — do NOT reveal phpinfo()
            // Just show a warning message or simplified info
            $lShowAdminPage = true;
            break;

        case "2":
        case "3":
        case "4":
        case "5":
            // Only admins can access the page — but still no phpinfo()
            if (!empty($_SESSION["is_admin"]) && $_SESSION["is_admin"] === true) {
                $lShowAdminPage = true;
            }
            break;
    }

    if ($lShowAdminPage) {

        // SAFE ALTERNATIVE: minimal diagnostic info instead of phpinfo()
        echo '<table>';
        echo '<tr><th>Server Diagnostic Summary (Safe)</th></tr>';
        echo '<tr><td>PHP Version: ' . htmlspecialchars(PHP_VERSION) . '</td></tr>';
        echo '<tr><td>Loaded Configuration File: ' . htmlspecialchars(php_ini_loaded_file()) . '</td></tr>';
        echo '<tr><td>Display Errors: ' . (ini_get("display_errors") ? "On" : "Off") . '</td></tr>';
        echo '<tr><td>Session Save Path: ' . htmlspecialchars(ini_get("session.save_path")) . '</td></tr>';
        echo '<tr><td>Timezone: ' . htmlspecialchars(ini_get("date.timezone")) . '</td></tr>';
        echo '</table>';

        echo '<p class="hint">Full system configuration is restricted for security reasons.</p>';

    } else {

        echo '<table><tr><td class="error-message">';
        echo 'Secure sites do not expose administrative or configuration pages to the Internet';
        echo '</td></tr></table>';

    }
?>
