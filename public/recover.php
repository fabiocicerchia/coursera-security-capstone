<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

function getClientIP() {
    $ipaddress = 'UNKNOWN';
    if (isset($_SERVER['HTTP_CLIENT_IP'])) {
        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    } else if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else if(isset($_SERVER['HTTP_X_FORWARDED'])) {
        $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    } else if(isset($_SERVER['HTTP_FORWARDED_FOR'])) {
        $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    } else if(isset($_SERVER['HTTP_FORWARDED'])) {
        $ipaddress = $_SERVER['HTTP_FORWARDED'];
    } else if(isset($_SERVER['REMOTE_ADDR'])) {
        $ipaddress = $_SERVER['REMOTE_ADDR'];
    }
    return $ipaddress;
}

$attempts = 0;
$error = false;
$captchaError = null;

if (!empty($_POST)) {
    $username = trim($_POST['username']);

    // validate captcha
    $captcha = filter_input(INPUT_POST, 'g-recaptcha-response', FILTER_SANITIZE_STRING);
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = ['secret' => RECAPTCHA_SERVER_KEY, 'response' => $captcha];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-type: application/x-www-form-urlencoded'
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1) ;
    $response = curl_exec($ch);
    curl_close($ch);
    $responseKeys = json_decode($response, true);
    $captchaError = !$responseKeys['success'];
    
    $iv = hash(HASH_ALGORITHM, GLOBAL_ENC_KEY, false);

    // encrypt email
    $usernameEnc = openssl_encrypt($username, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

    $stmt = $dbh->prepare("SELECT id, email FROM users WHERE username = :username AND active = true LIMIT 1");
    $stmt->execute([':username' => $usernameEnc]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt = null;
    $userId = $row['id'];
    $emailEnc = $row['email'];

    // decrypt email
    $email = openssl_decrypt($emailEnc, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

    if ($emailEnc) {
	$iv = hash(HASH_ALGORITHM, $email . GLOBAL_ENC_KEY, false);

        // generate Token
	$token = hash(HASH_ALGORITHM, bin2hex(openssl_random_pseudo_bytes(64)), false);
	$token = openssl_encrypt($token, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

        // handle IP
	$ipAddress = ip2long(getClientIP());
	$ipAddress = openssl_encrypt($ipAddress, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);

	// let the other tokens expire
	$stmt = $dbh->prepare("UPDATE tokens SET expire = current_timestamp WHERE user_id = :user_id;");
        $stmt->execute([':user_id' => $userId]);

	$stmt = $dbh->prepare("INSERT INTO tokens (user_id, reset_token, expire, used, ip_request) VALUES (?, ?, current_timestamp + interval '6 hours', false, ?);");
        $stmt->execute([$userId, $token, $ipAddress]);

	// send email
        $link = 'https://coursera-security-capstone.herokuapp.com/reset.php?t=' . rawurlencode($token);

	// Create the Transport
	$transport = (new Swift_SmtpTransport(SMTP_HOSTNAME, SMTP_PORT))
		->setUsername(SMTP_USERNAME)
		->setPassword(SMTP_PASSWORD)
		;

	// Create the Mailer using your created Transport
	$mailer = new Swift_Mailer($transport);

        $body = "Hi,\n\ntoday at %s someone with IP: %s requested a password reset.\nIf you didn't do it just ignore this email.\nIf you want to reset your password click on this link: %s\n\nThank you";
        $body = sprintf($body, date('H:i:s'), getClientIP(), $link);

	// Create a message
	$message = (new Swift_Message('Reset Password Link'))
		->setFrom(['noreply@coursera-security-capstone.herokuapp.com' => 'Coursera Security Capstone'])
		->setTo([$email])
		->setBody($body)
		;

	// Send the message
	$result = $mailer->send($message);
    }
}

ob_start(); ?>
<script src="https://www.google.com/recaptcha/api.js?render=<?php echo htmlspecialchars(RECAPTCHA_CLIENT_KEY); ?>" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>"></script>
<script nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
grecaptcha.ready(() => {
    grecaptcha.execute('<?php echo htmlspecialchars(RECAPTCHA_CLIENT_KEY); ?>', {action: 'login'}).then((token) => {
        document.getElementById('g-recaptcha-response').value = token;
    });
});
</script>
<form class="form-signin" method="post">
    <h1 class="h3 mb-3 font-weight-normal">Reset Password</h1>
    <?php if ($captchaError): ?>
    <div class="alert alert-danger" role="alert">Our captcha blocked you, if you think you've got blocked by mistake contact us.</div>
    <?php else: ?>
    <label for="inputUsername" class="sr-only">Username</label>
    <input type="text" id="inputUsername" name="username" class="form-control" placeholder="Username" required autofocus value="<?php echo htmlspecialchars($_REQUEST['username'] ?? null); ?>">
    <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response" value="">
    <?php if ($email !== null): ?>
    <div class="alert alert-success" role="alert">If the account exists will receive soon a reset link in the inbox</div>
    <?php else: ?>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Send Reset Link</button>
    <?php endif; ?>
    <?php endif; ?>
</form>
<div id="recaptcha_field"></div>
<?php $tplBody = ob_get_clean(); ?>
<?php require_once __DIR__ . '/../src/tpl/base.php'; ?>
