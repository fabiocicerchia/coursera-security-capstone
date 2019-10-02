<?php

define('HASH_ALGORITHM', getenv('HASH_ALGORITHM'));
define('CRYPT_ALGORITHM', getenv('CRYPT_ALGORITHM'));
define('CSP_TOKEN', hash(HASH_ALGORITHM, bin2hex(openssl_random_pseudo_bytes(64)), false));
define('GLOBAL_ENC_KEY', getenv('GLOBAL_ENC_KEY'));

define('RECAPTCHA_CLIENT_KEY', getenv('RECAPTCHA_CLIENT_KEY'));
define('RECAPTCHA_SERVER_KEY', getenv('RECAPTCHA_SERVER_KEY'));

define('DB_DSN', getenv('DB_DSN'));

define('SMTP_HOSTNAME', getenv('SMTP_HOSTNAME'));
define('SMTP_PORT', getenv('SMTP_PORT'));
define('SMTP_USERNAME', getenv('SMTP_USERNAME'));
define('SMTP_PASSWORD', getenv('SMTP_PASSWORD'));
