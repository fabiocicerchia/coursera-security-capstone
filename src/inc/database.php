<?php

require_once __DIR__ . '/../lib/Encrypt.php';

$e = new \App\Encrypt();

try {
    $dbh = new \PDO(DB_DSN, DB_USER, DB_PASS);
    $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die('Connection failed' . $e->getMessage());
}
