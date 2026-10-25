<?php
$password = $_POST['password'];
$hash = md5($password);
$legacy_hash = sha1($password);
$out = preg_replace('/x/e', 'phpinfo()', $input);
