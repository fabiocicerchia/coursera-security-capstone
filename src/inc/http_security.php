<?php

header("Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-".CSP_TOKEN."'; connect-src 'self'; img-src 'self'; style-src 'self' 'nonce-".CSP_TOKEN."'; frame-src 'self' www.google.com");
