<?php
/* The identical source is used for baseline, clean and crash requests. */
function command($db, array $args): string {
    $wire = '*' . count($args) . "\r\n";
    foreach ($args as $arg) $wire .= '$' . strlen($arg) . "\r\n" . $arg . "\r\n";
    if (fwrite($db, $wire) !== strlen($wire)) throw new RuntimeException('database write');
    $reply = fgets($db);
    if ($reply === false || $reply[0] === '-') throw new RuntimeException('database rejected command');
    if ($reply[0] === '$') {
        $length = (int)substr($reply, 1);
        if ($length < 0) return '';
        $data = '';
        while (strlen($data) < $length + 2) {
            $part = fread($db, $length + 2 - strlen($data));
            if ($part === false || $part === '') throw new RuntimeException('database read');
            $data .= $part;
        }
        return substr($data, 0, $length);
    }
    return $reply;
}
$id = $_POST['id'];
$db = fopen(getenv('DB_DSN'), 'r+');
if ($db === false) throw new RuntimeException('database connection');
command($db, ['SET', 'row:' . $id, 'valid:' . $id]);
command($db, ['SET', 'session:' . $id, 'active']);
if (command($db, ['GET', 'row:' . $id]) !== 'valid:' . $id) throw new RuntimeException('read your writes');
fclose($db);
echo json_encode(['id' => $id, 'ok' => true], JSON_THROW_ON_ERROR);
