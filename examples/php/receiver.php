<?php
// Benign test receiver, always run on a patched local PHP build.
header('Content-Type: application/json');
$id = preg_replace('/[^A-Za-z0-9_-]/', '', $_SERVER['HTTP_X_TEST_ID'] ?? '');
error_log('HOTFILTER_UPSTREAM ' . $id);
$files = [];
foreach ($_FILES as $name => $file) {
    if (is_array($file['tmp_name'])) {
        foreach ($file['tmp_name'] as $i => $path) {
            $files[] = ['name' => $name, 'size' => $file['size'][$i], 'error' => $file['error'][$i],
                'sha256' => is_uploaded_file($path) ? hash_file('sha256', $path) : null];
        }
    } else {
        $files[] = ['name' => $name, 'size' => $file['size'], 'error' => $file['error'],
            'sha256' => is_uploaded_file($file['tmp_name']) ? hash_file('sha256', $file['tmp_name']) : null];
    }
}
echo json_encode(['receiver' => 'patched-php-fpm', 'php_version' => PHP_VERSION,
    'id' => $id, 'pid' => getmypid(), 'files' => $files, 'fields' => count($_POST)]);
