<?php

require_once __DIR__ . '/../src/inc/config.php';
require_once __DIR__ . '/../src/inc/php_security.php';

ob_start(); ?>
<link href="https://getbootstrap.com/docs/4.3/examples/cover/cover.css" rel="stylesheet" nonce="<?php echo htmlspecialchars(CSP_TOKEN); ?>">
<div class="cover-container d-flex w-100 h-100 p-3 mx-auto flex-column">
    <header class="masthead mb-auto">
        <div class="inner">
            <h3 class="masthead-brand">Coursera Security Capstone</h3>
            <nav class="nav nav-masthead justify-content-center">
                <a class="nav-link active" href="#">Home</a>
                <a class="nav-link" href="/signup.php">Sign Up</a>
                <a class="nav-link" href="/login.php">Login</a>
            </nav>
        </div>
    </header>
    <main class="inner cover">
        <h1 class="cover-heading">Coursera Security Capstone.</h1>
        <p class="lead">Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus venenatis eget magna et iaculis. Nam nec blandit risus, in dictum diam. Donec gravida maximus diam, vitae tincidunt lorem hendrerit et.</p>
    </main>
    <footer class="mastfoot mt-auto">
        <div class="inner">
            <p>&copy; 2019 Fabio Cicerchia</p>
        </div>
    </footer>
</div>
<?php $tplBody = ob_get_clean(); ?>
<?php require_once __DIR__ . '/../src/tpl/base.php'; ?>
