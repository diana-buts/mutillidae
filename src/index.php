<?php

/* ------------------------------------------
 * Constants used in application
 * ------------------------------------------ */
require_once './includes/constants.php';

/* ------------------------------------------------------
 * INCLUDE CLASS DEFINITION PRIOR TO INITIALIZING SESSION
 * ------------------------------------------------------ */
require_once __SITE_ROOT__.'/classes/EncodingHandler.php';
require_once __SITE_ROOT__.'/classes/MySQLHandler.php';
require_once __SITE_ROOT__.'/classes/SQLQueryHandler.php';
require_once __SITE_ROOT__.'/classes/CustomErrorHandler.php';
require_once __SITE_ROOT__.'/classes/LogHandler.php';
require_once __SITE_ROOT__.'/classes/RemoteFileHandler.php';
require_once __SITE_ROOT__.'/classes/RequiredSoftwareHandler.php';

/* ------------------------------------------
 * INITIALIZE SESSION
 * ------------------------------------------ */
if (session_status() == PHP_SESSION_NONE){
    session_start();
}

if (!isset($_SESSION["security-level"])){
    $_SESSION["security-level"] = 0;
}

/* ----------------------------------------------------
 * ENFORCE SSL
 * ---------------------------------------------------- */
if (!isset($_SESSION["EnforceSSL"])){
    $_SESSION["EnforceSSL"] = "False";
}

switch ($_SESSION["security-level"]){
    case "0":
    case "1":
        if ($_SESSION["EnforceSSL"] == "True"){
            if(!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS']!="on"){
                $lSecureRedirect = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
                header("Location: $lSecureRedirect");
                exit();
            }
        }
    break;

    case "2":
    case "3":
    case "4":
    case "5":
        if ($_SESSION["EnforceSSL"] == "True"){
            if(!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS']!="on"){
                require_once 'ssl-enforced.php';
                exit();
            }
        }
    break;
}

/* ----------------------------------------------------
 * Initialize logged in status
 * ---------------------------------------------------- */
if (!isset($_SESSION["user_is_logged_in"])){
    $_SESSION["user_is_logged_in"] = false;
    $_SESSION["logged_in_user"] = '';
    $_SESSION["logged_in_user_signature"] = '';
    $_SESSION["uid"] = '';
    $_SESSION["is_admin"] = false;
}

/* ----------------------------------------------------
 * Check database error bypass
 * ---------------------------------------------------- */
if (!isset($_SESSION["UserOKWithDatabaseFailure"])) {
    $_SESSION["UserOKWithDatabaseFailure"] = false;
}

/* ------------------------------------------
 * initialize showhints session and cookie
 * ------------------------------------------ */
if (isset($_COOKIE["showhints"])){
    $l_showhints = $_COOKIE["showhints"];
}else{
    $l_showhints = 1;
    switch ($_SESSION["security-level"]){
        case "0":
        case "1":
            $lProtectCookies = false;
        break;

        case "2":
        case "3":
        case "4":
        case "5":
            $lProtectCookies = true;
        break;
    }

    $l_cookie_options = [
        'expires' => 0,
        'path' => '/',
        'secure' => false,
        'httponly' => false,
        'samesite' => 'Lax'
    ];

    if ($lProtectCookies){
        $l_cookie_options['samesite'] = 'Strict';
    }

    setcookie('showhints', $l_showhints, $l_cookie_options);
}

if (!isset($_SESSION["showhints"]) || ($_SESSION["showhints"] != $l_showhints)){
    $_SESSION["showhints"] = $l_showhints;
    $_SESSION["hints-enabled"] = ($l_showhints === 0) ? "Disabled" : "Enabled";
}

/* ------------------------------------------
 * initialize Encoder
 * ------------------------------------------ */
$Encoder = new EncodingHandler();

/* ------------------------------------------
 * Test for database availability
 * ------------------------------------------ */
function handleException(){
    restore_exception_handler();
    header("Location: database-offline.php", true, 302);
    exit();
}

if (!$_SESSION["UserOKWithDatabaseFailure"]) {
    set_exception_handler('handleException');
    MySQLHandler::databaseAvailable();
    restore_exception_handler();
}

/* ------------------------------------------
 * initialize custom error handler
 * ------------------------------------------ */
$CustomErrorHandler = new CustomErrorHandler($_SESSION["security-level"]);

/* ------------------------------------------
 * initialize log handler
 * ------------------------------------------ */
$LogHandler = new LogHandler($_SESSION["security-level"]);

/* ------------------------------------------
 * initialize MySQL handler
 * ------------------------------------------ */
$MySQLHandler = new MySQLHandler($_SESSION["security-level"]);
$MySQLHandler->connectToDefaultDatabase();

/* ------------------------------------------
 * initialize SQL Query handler
 * ------------------------------------------ */
$SQLQueryHandler = new SQLQueryHandler($_SESSION["security-level"]);

/* ------------------------------------------
 * initialize remote file handler
 * ------------------------------------------ */
$RemoteFileHandler = new RemoteFileHandler($_SESSION["security-level"]);

/* ------------------------------------------
 * initialize required software handler
 * ------------------------------------------ */
$RequiredSoftwareHandler = new RequiredSoftwareHandler($_SESSION["security-level"]);

/* ------------------------------------------
 * PROCESS REQUESTS
 * ------------------------------------------ */
if (isset($_GET["do"])){
    include_once __SITE_ROOT__.'/includes/process-commands.php';
}

/* ------------------------------------------
 * PROCESS LOGIN ATTEMPT
 * ------------------------------------------ */
if (isset($_POST["login-php-submit-button"])){
    include_once __SITE_ROOT__.'/includes/process-login-attempt.php';
}

/* ------------------------------------------
 * REACT TO CLIENT SIDE CHANGES
 * ------------------------------------------ */
switch ($_SESSION["security-level"]){
    case "0":
    case "1":
        if (isset($_COOKIE['uid'])){
            try{
                $lQueryResult = $SQLQueryHandler->getUserAccountByID($_COOKIE['uid']);
                if ($lQueryResult->num_rows > 0) {
                    $row = $lQueryResult->fetch_object();
                    $_SESSION["user_is_logged_in"] = true;
                    $_SESSION["uid"] = $row->cid;
                    $_SESSION["logged_in_user"] = $row->username;
                    $_SESSION["logged_in_user_signature"] = $row->mysignature;
                    $_SESSION["is_admin"] = $row->is_admin;
                    header('Logged-In-User: '.$_SESSION["logged_in_user"], true);
                }
            } catch (Exception $e) {
                echo $CustomErrorHandler->FormatError($e, $lQueryString);
            }
        } else if (isset($_SESSION["logged_in_user"])) {
            header('Logged-In-User: '.$_SESSION["logged_in_user"], true);
        }
    break;

    case "2":
    case "3":
    case "4":
    case "5":
        if (isset($_SESSION["logged_in_user"])){
            header('Logged-In-User: '.$Encoder->encodeForHTML($_SESSION["logged_in_user"]), true);
        }
    break;
}

/* ------------------------------------------
 * Security Headers (Modern Browsers)
 * ------------------------------------------ */
// ... (зберігаємо всі існуючі заголовки без змін)

/* ------------------------------------------
 * Set the HTTP content-type of this page
 * ------------------------------------------ */
header("Content-Type: text/html;charset=UTF-8", true);

/* ------------------------------------------
 * SAFE PAGE INCLUDE
 * ------------------------------------------ */
require_once __SITE_ROOT__."/includes/header.php";

$allowedPages = [
    'home.php',
    'index.php',
    'login.php',
    'register.php',
    'set-security-level.php',
    'view-logs.php',
    'user-info.php',
    'dns-lookup.php',
    'echo.php',
    'phpinfo.php',
    'page-not-found.php'
];

$pageParam = $_GET['page'] ?? 'home.php';

if (
    strpos($pageParam, '..') !== false ||
    preg_match('/[\0-\x1F\x7F]/', $pageParam) ||
    preg_match('/^(php|file|data|ftp|zip|phar):/i', $pageParam)
) {
    $pageParam = 'home.php';
}

if (in_array($pageParam, $allowedPages, true)) {
    $lPage = realpath(__SITE_ROOT__ . '/pages/' . $pageParam);
} else {
    $lPage = __SITE_ROOT__.'/page-not-found.php';
}

if (file_exists($lPage) && strpos($lPage, realpath(__SITE_ROOT__)) === 0) {
    require_once $lPage;
} else {
    require_once __SITE_ROOT__.'/page-not-found.php';
}

require_once __SITE_ROOT__."/includes/information-disclosure-comment.php";
require_once __SITE_ROOT__."/includes/footer.php";

/* ------------------------------------------
 * LOG USER VISIT TO PAGE
 * ------------------------------------------ */
include_once __SITE_ROOT__."/includes/log-visit.php";

/* ------------------------------------------
 * CLOSE DATABASE CONNECTION
 * ------------------------------------------ */
$MySQLHandler->closeDatabaseConnection();

?>
