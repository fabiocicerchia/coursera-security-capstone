<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

use ZxcvbnPhp\Zxcvbn;

$strength = null;
$errorEmail = $errorUsername = $errorStrength = false;

if (!empty($_POST)) {
    $email    = trim($_POST['email']);
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // check password strength
    $userData = [$email, $username];
    $zxcvbn = new Zxcvbn();
    $strength = $zxcvbn->passwordStrength($password, $userData);
    $errorStrength = $strength !== null && $strength < 3;

    // validate email
    $errorEmail = filter_var($email, FILTER_VALIDATE_EMAIL) === false;
    if ($errorEmail === false) {
        $stmt = $dbh->prepare('SELECT COUNT(*) AS cnt FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt = null;
        $errorEmail = ((int) $row['cnt']) > 0;
    }

    // generate hash
    $seed = hash(HASH_ALGORITHM, bin2hex(openssl_random_pseudo_bytes(64)), false);
    $hash = hash(HASH_ALGORITHM, $seed . $email, false);

    $iv = hash(HASH_ALGORITHM, GLOBAL_ENC_KEY, false);

    // encrypt username
    $usernameEnc = openssl_encrypt($username, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

    // validate username
    $stmt = $dbh->prepare('SELECT COUNT(*) AS cnt FROM users WHERE username = :username LIMIT 1');
    $stmt->execute([':username' => $usernameEnc]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt = null;
    $errorUsername = empty($username) || ((int) $row['cnt']) > 0;

    // process signup (all validation passed)
    if ($errorStrength === false && $errorEmail === false && $errorUsername === false) {
        // encrypt email
	$emailEnc = openssl_encrypt($email, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

        // salt generation & hash password
	$salt = hash(HASH_ALGORITHM, bin2hex(openssl_random_pseudo_bytes(64)), false);
	$password = hash(HASH_ALGORITHM, $password, false); // this is to avoid to pass the clean password over the net during login
	$password = hash(HASH_ALGORITHM, $salt . $password, false);

        // generate private & public keys
	$config = array(
            'digest_alg' => 'sha512',
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
	);
	$res = openssl_pkey_new($config);
	openssl_pkey_export($res, $privKey);
	$pubKey = openssl_pkey_get_details($res);
	$pubKey = $pubKey['key'];

        // encrypt private & public keys
	$privKey = openssl_encrypt($privKey, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);
	$pubKey  = openssl_encrypt($pubKey, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

        // insert into db
        $stmt = $dbh->prepare('INSERT INTO users (hash, username, email, password, salt, key_priv, key_pub, active) VALUES (?, ?, ?, ?, ?, ?, ?, true);');
        $stmt->execute([$hash, $usernameEnc, $emailEnc, $password, $salt, $privKey, $pubKey]);

        header('Location: /login.php?s=1');
    }
}

ob_start(); ?>
<script src="/zxcvbn.js" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
<form class="form-signin" method="post">
    <h1 class="h3 mb-3 font-weight-normal">Sign Up</h1>
    <label for="inputEmail" class="sr-only">Email address</label>
    <input type="email" id="inputEmail" name="email" class="form-control" placeholder="Email address" required autofocus value="<?php echo htmlspecialchars($_POST['email'] ?? null); ?>">
    <?php if ($errorEmail === true): ?>
    <div class="alert alert-danger" role="alert">The email is already taken, please <a href="/login.php">log in</a>.</div>
    <?php endif; ?>
    <label for="inputUsername" class="sr-only">Username</label>
    <input type="text" id="inputUsername" name="username" class="form-control" placeholder="Username" required value="<?php echo htmlspecialchars($_POST['username'] ?? null); ?>">
    <?php if ($errorUsername === true): ?>
    <div class="alert alert-danger" role="alert">The username is already taken, please choose another one.</div>
    <?php endif; ?>
    <label for="inputPassword" class="sr-only">Password</label>
    <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required value="">
    <?php if ($strength === null || $errorStrength === true): ?>
    <div id="weak_password" class="alert alert-danger<?php if ($strength === null): ?> d-none<?php endif; ?>" role="alert">The password is too insecure.</div>
    <?php endif; ?>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Sign Up</button>
</form>
<script nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
function getStrength() {
    var email    = document.getElementById('inputEmail').value;
    var username = document.getElementById('inputUsername').value;
    var password = document.getElementById('inputPassword').value;

    var r = zxcvbn(password, [email, username]);
    return r;
}
$('#inputPassword').keyup(function(e) {
    var r = getStrength();
    if (r.score < 3) {
	$('#weak_password').removeClass('d-none');
	$('#weak_password').html('<strong>' + r.feedback.warning + '</strong><ul><li>' + r.feedback.suggestions.join('</li></li>') + '</li></ul>');
	$('form [type="submit"]').attr('disabled', 'didsabled');
    } else {
	$('#weak_password').addClass('d-none');
	$('form [type="submit"]').removeAttr('disabled');
    }
});
$('form.form-signin').submit(function(e) {
    var r = getStrength();
    if (r.score < 3) {
	$('#weak_password').removeClass('d-none');
	$('#weak_password').html('<strong>' + r.feedback.warning + '</strong><ul><li>' + r.feedback.suggestions.join('</li></li>') + '</li></ul>');
	$('form [type="submit"]').attr('disabled', 'didsabled');
	e.preventDefault();
    }
});
</script>
<?php $tplBody = ob_get_clean(); ?>
<?php require_once __DIR__ . '/../src/tpl/base.php'; ?>
