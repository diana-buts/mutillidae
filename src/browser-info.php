<?php

    try{
       switch ($_SESSION["security-level"]){
          default: // This code is insecure
              case "0":
              case "1":
             $lEncodeOutput = false;
             $luseSafeJavaScript = "false";
          break;

          case "2":
          case "3":
          case "4":
          case "5":
             $lEncodeOutput = true;
             $luseSafeJavaScript = "true";
          break;
       }

       require_once __SITE_ROOT__.'/classes/ClientInformationHandler.php';
       $lClientInformationHandler = new ClientInformationHandler();

       if ($lEncodeOutput){
          $lWhoIsInformation = $Encoder->encodeForHTML($lClientInformationHandler->whoIsClient());
          $lOperatingSystem = $Encoder->encodeForHTML($lClientInformationHandler->getOperatingSystem());
          $lBrowser = $Encoder->encodeForHTML($lClientInformationHandler->getBrowser());
          $lClientHostname = $Encoder->encodeForHTML($lClientInformationHandler->getClientHostname());
          $lClientIP = $Encoder->encodeForHTML($lClientInformationHandler->getClientIP());
          $lClientUserAgentString = $Encoder->encodeForHTML($lClientInformationHandler->getClientUserAgentString());

          // FIX: Sensitive info — show referrer only to admin
          if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
              $lClientReferrer = $Encoder->encodeForHTML($lClientInformationHandler->getClientReferrer());
          } else {
              $lClientReferrer = "Hidden for privacy"; // FIX
          }

          $lClientPort = $Encoder->encodeForHTML($lClientInformationHandler->getClientPort());

       } else {

          $lWhoIsInformation = $lClientInformationHandler->whoIsClient();
          $lOperatingSystem = $lClientInformationHandler->getOperatingSystem();
          $lBrowser = $lClientInformationHandler->getBrowser();
          $lClientHostname = $lClientInformationHandler->getClientHostname();
          $lClientIP = $lClientInformationHandler->getClientIP();
          $lClientUserAgentString = $lClientInformationHandler->getClientUserAgentString();

          // FIX (non-encoded insecure branch) — still protect privacy
          if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
              $lClientReferrer = $lClientInformationHandler->getClientReferrer();
          } else {
              $lClientReferrer = "Hidden for privacy";
          }

          $lClientPort = $lClientInformationHandler->getClientPort();
       }

    } catch (Exception $e) {
       echo $CustomErrorHandler->FormatError($e, "Error collecting browser information");
    }
?>

<div class="page-title">Browser Information</div>

<?php include_once __SITE_ROOT__.'/includes/back-button.inc';?>
<?php include_once __SITE_ROOT__.'/includes/hints/hints-menu-wrapper.inc'; ?>

<table style="width:75%;" class="results-table">
    <tr class="report-header"><td colspan="3">Info obtained by PHP</td></tr>
    <tr><th class="report-label">Client IP</th><td class="report-data"><?php echo $lClientIP; ?></td></tr>
    <tr><th class="report-label">Client Hostname</th><td class="report-data"><?php echo $lClientHostname; ?></td></tr>
    <tr><th class="report-label">Operating System</th><td class="report-data"><?php echo $lOperatingSystem ?></td></tr>
    <tr><th class="report-label">User Agent String</th><td class="report-data"><?php echo $lClientUserAgentString; ?></td></tr>

    <!-- FIX: Privacy-safe referrer -->
    <tr><th class="report-label">Referrer</th><td class="report-data"><?php echo $lClientReferrer; ?></td></tr>

    <tr><th class="report-label">Remote Client Port</th><td class="report-data"><?php echo $lClientPort; ?></td></tr>

    <?php if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']): ?>
        <tr><th class="report-label">WhoIs info for client IP</th><td class="report-data"><pre><?php echo $lWhoIsInformation; ?></pre></td></tr>
    <?php endif; ?>

    <?php if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']): ?>
        <?php
        if ($lEncodeOutput){
            foreach ($_COOKIE as $key => $value){
                echo '<tr><th class="report-label">Cookie '.$Encoder->encodeForHTML($key).'</th><td class="report-data">'.$Encoder->encodeForHTML($value).'</td></tr>';
            }
        } else {
            foreach ($_COOKIE as $key => $value){
                echo '<tr><th class="report-label">Cookie '.$key.'</th><td class="report-data">'.$value.'</td></tr>';
            }
        }
        ?>
    <?php endif; ?>

</table>
