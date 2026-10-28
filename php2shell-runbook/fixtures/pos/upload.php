<?php
// positive fixture: a real use of the session upload-progress feature
$key = ini_get("session.upload_progress.prefix") . "myform";
if (!empty($_SESSION[$key])) {
    $pct = $_SESSION[$key]["bytes_processed"] / $_SESSION[$key]["content_length"];
    echo json_encode(["progress" => $pct]);
}
