<?php
// negative fixture: ordinary file handling, no progress-tracking session feature
$f = $_FILES["doc"]["tmp_name"] ?? null;
if ($f && is_uploaded_file($f)) { move_uploaded_file($f, "/var/data/doc.pdf"); }
echo "ok";
