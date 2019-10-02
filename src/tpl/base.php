<?php

require_once __DIR__ . '/../inc/http_security.php';

?><!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Coursera Security Capstone</title>
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous" nonce="<?php echo CSP_TOKEN ;?>">
        <link href="https://getbootstrap.com/docs/4.3/examples/sign-in/signin.css" rel="stylesheet" nonce="<?php echo CSP_TOKEN ;?>">
        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous" nonce="<?php echo CSP_TOKEN ;?>"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous" nonce="<?php echo CSP_TOKEN ;?>"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous" nonce="<?php echo CSP_TOKEN ;?>"></script>
	<style nonce="<?php echo CSP_TOKEN; ?>">
            body { box-shadow: inset 0 0 5rem rgba(0, 0, 0, .5); background-color: #333; }
            .alert { font-size: 0.8em; }
            .form-signin { background: white; border-radius: 10px; }
            .form-signin #inputUsername { border-radius: 0; }
            #weak_password ul { text-align: left; margin-bottom: 0; }
        </style>
    </head>
    <body class="text-center">
        <?php echo $tplBody; ?>
    </body>
</html>
