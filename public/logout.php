<?php

session_name('CSCSI'); // Coursera Security Capstone Session Id
session_start();
session_destroy();
$_SESSION = [];
header('Location: /login.php');
