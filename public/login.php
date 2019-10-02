<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/database.php';
require_once __DIR__ . '/../src/inc/php_security.php';

$attempts = 0;
$error = false;
$csrfTokenError = false;
$username = null;

session_name('CSCSI'); // Coursera Security Capstone Session Id
session_start();
if (empty($_SESSION['token'])) {
    $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
}

if (!empty($_SESSION['user'])) {
    header('Location: /messages.php');
    exit;
}

if (!empty($_POST)) {
    if ($_SESSION['token'] !== $_POST['_token']) {
        $csrfTokenError = true;
        $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
    } else {
        unset($_SESSION['token']);

        $username = trim($_POST['username']);
        $password = $_POST['password'];
        
        $iv = hash(HASH_ALGORITHM, GLOBAL_ENC_KEY, false);
        
        // encrypt username
        $usernameEnc = openssl_encrypt($username, CRYPT_ALGORITHM, GLOBAL_ENC_KEY, 0, $iv);
        
        // hash password
        $password = hash(HASH_ALGORITHM, $password, false);
        
        $stmt = $dbh->prepare("SELECT COUNT(*) AS cnt FROM users WHERE username = :username AND password = ENCODE(DIGEST(concat(salt, cast(:password as text)), 'sha256'), 'hex') AND (locked_until IS NULL OR locked_until < current_timestamp) LIMIT 1");
        $stmt->execute([':username' => $usernameEnc, ':password' => $password]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt = null;
        $error = ((int) $row['cnt']) === 0;
        
        if ($error === true) {
            $stmt = $dbh->prepare("UPDATE users SET attempts = attempts + 1, locked_until = (CASE WHEN attempts > 3 THEN (current_timestamp + interval '5 minutes') ELSE NULL END) WHERE username = :username");
            $stmt->execute([':username' => $usernameEnc]);
        
            $stmt = $dbh->prepare('SELECT attempts FROM users WHERE username = :username LIMIT 1');
            $stmt->execute([':username' => $usernameEnc]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $stmt = null;
            $attempts = (int) $row['attempts'];
        } else {
            $stmt = $dbh->prepare("UPDATE users SET attempts = 0, locked_until = NULL WHERE username = :username");
            $stmt->execute([':username' => $usernameEnc]);
        
	    $_SESSION['user'] = $usernameEnc;
        
            header('Location: /messages.php');
        }
    }
}

ob_start(); ?>
<form class="form-signin" method="post">
    <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
    <?php if (!empty($_GET['s']) && $_GET['s'] === '1'): ?>
    <div class="alert alert-success" role="alert">You've signed up successfully, please log in using your credentials.</div>
    <?php endif; ?>
    <label for="inputUsername" class="sr-only">Username</label>
    <input type="text" id="inputUsername" name="username" class="form-control" placeholder="Username" required autofocus value="<?php echo htmlspecialchars($username ?? null); ?>">
    <label for="inputPassword" class="sr-only">Password</label>
    <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required value="">
    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['token']); ?>" />
    <?php if ($csrfTokenError === true): ?>
    <div class="alert alert-danger" role="alert">CSRF Token Error. Try refreshing the webpage before trying again.</div>
    <?php elseif ($error === true): ?>
    <?php if ($attempts > 3): ?>
    <div class="alert alert-danger" role="alert">Account locked after too many tries.<br />If you have forgot the password try to <a href="/recover.php?username=<?php echo rawurlencode(htmlspecialchars($username ?? null)); ?>">recover it</a>.</div>
    <?php else: ?>
    <div class="alert alert-danger" role="alert">Username or password not correct.</div>
    <?php endif; ?>
    <?php endif; ?>
    <button class="btn btn-lg btn-primary btn-block" type="submit">Log In</button>
    <small><a href="/recover.php">forgot password?</a></small>
</form>
<?php $tplBody = ob_get_clean(); ?>
<?php require_once __DIR__ . '/../src/tpl/base.php'; ?>
