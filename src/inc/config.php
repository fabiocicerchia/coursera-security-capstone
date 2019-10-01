<?php

define('HASH_ALGORITHM', getenv('HASH_ALGORITHM'));
define('CSP_TOKEN', hash(HASH_ALGORITHM, microtime(true) . uniqid(), false));
define('GLOBAL_ENC_KEY', getenv('GLOBAL_ENC_KEY'));

define('DB_DSN', getenv('DATABASE_URL'));
define('DB_USER', 'usr');
define('DB_PASS', 'psw');
