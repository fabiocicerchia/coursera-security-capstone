<?php

require_once __DIR__ . '/../lib/Encrypt.php';

$e = new \App\Encrypt();

try {
    $dbh = new \PDO(DB_DSN);
    $dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    $dbh->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);
    $dbh->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die('Connection failed');
}
