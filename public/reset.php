<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

use ZxcvbnPhp\Zxcvbn;

$strength = null;
$errorStrength = false;

$token = $_GET['t'];

$stmt = $dbh->prepare("SELECT users.username FROM tokens INNER JOIN users ON users.id = tokens.user_id WHERE tokens.reset_token = :token AND tokens.used = false AND tokens.expire >= current_timestamp LIMIT 1");
$stmt->execute([':token' => $token]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
$stmt = null;
$usernameEnc = $row['username'];

$iv = hash(HASH_ALGORITHM, GLOBAL_ENC_KEY, false);

// decrypt username
$username = openssl_decrypt($usernameEnc, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

if (!empty($_POST)) {
    $password = $_POST['password'];

    $stmt = $dbh->prepare("SELECT email FROM users WHERE username = :username AND active = true LIMIT 1");
    $stmt->execute([':username' => $usernameEnc]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt = null;
    $emailEnc = $row['email'];

    // decrypt email
    $email = openssl_decrypt($emailEnc, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

    // check password strength
    $userData = [$email, $username];
    $zxcvbn = new Zxcvbn();
    $strength = $zxcvbn->passwordStrength($password, $userData);
    $errorStrength = $strength !== null && $strength < 3;

    if ($errorStrength === false && !empty($username)) {
        // salt generation & hash password
        $salt = hash(HASH_ALGORITHM, bin2hex(openssl_random_pseudo_bytes(64)), false);
        $password = hash(HASH_ALGORITHM, $password, false); // this is to avoid to pass the clean password over the net during login
        $password = hash(HASH_ALGORITHM, $salt . $password, false);

        $stmt = $dbh->prepare("UPDATE users SET attempts = 0, locked_until = NULL, password = :password, salt = :salt WHERE username = :username");
        $stmt->execute([':username' => $usernameEnc, ':password' => $password, ':salt' => $salt]);

        $stmt = $dbh->prepare("UPDATE tokens SET used = true WHERE reset_token = :token");
        $stmt->execute([':token' => $token]);

	// send email
        $link = 'https://coursera-security-capstone.herokuapp.com/login.php';
	
	// Create the Transport
	$transport = (new Swift_SmtpTransport(SMTP_HOSTNAME, SMTP_PORT))
		->setUsername(SMTP_USERNAME)
		->setPassword(SMTP_PASSWORD)
		;

	// Create the Mailer using your created Transport
	$mailer = new Swift_Mailer($transport);

        $body = "Hi,\n\nwe wanted to notify you that you've changed the password correctly.\nPlease log in here: %s";
        $body = sprintf($body, $link);

	// Create a message
	$message = (new Swift_Message('Password Changed Successfully'))
		->setFrom(['noreply@coursera-security-capstone.herokuapp.com' => 'Coursera Security Capstone'])
		->setTo([$email])
		->setBody($body)
		;

	// Send the message
	$result = $mailer->send($message);

        header('Location: /login.php');
    }
}

ob_start(); ?>
<script src="/zxcvbn.js" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
<form class="form-signin" method="post">
    <h1 class="h3 mb-3 font-weight-normal">Reset Password</h1>
    <?php if (!$username): ?>
    <div class="alert alert-danger" role="alert">The token is invalid or expired.</div>
    <?php else: ?>
    <label for="inputPassword" class="sr-only">Password</label>
    <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required value="">
    <?php if ($strength === null || $errorStrength === true): ?>
    <div id="weak_password" class="alert alert-danger<?php if ($strength === null): ?> d-none<?php endif; ?>" role="alert">The password is too insecure.</div>
    <?php endif; ?>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Change Password</button>
    <?php endif; ?>
</form>
<script nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
function getStrength() {
    var password = document.getElementById('inputPassword').value;

    var r = zxcvbn(password);
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
