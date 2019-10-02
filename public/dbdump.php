<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

$zip = new ZipArchive();
$filename = tempnam(sys_get_temp_dir(), 'CSC');

if ($zip->open($filename, ZipArchive::CREATE) !== true) {
    die('cannot open file');
}

// messages
$stmt = $dbh->prepare("SELECT * FROM messages");
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$stmt = null;
$zip->addFromString('messages.txt', var_export($rows, true));

// tokens
$stmt = $dbh->prepare("SELECT * FROM tokens");
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$stmt = null;
$zip->addFromString('tokens.txt', var_export($rows, true));

// users
$stmt = $dbh->prepare("SELECT * FROM users");
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$stmt = null;
$zip->addFromString('users.txt', var_export($rows, true));

$zip->close();

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="dbdump-'.date('YmdHis').'.zip"');
header('Expires: 0');
header('Cache-Control: no-cache');
header('Content-Length: ' . filesize($filename));
readfile($filename);

unlink($filename);
