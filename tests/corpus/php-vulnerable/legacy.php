<?php
function __autoload($class) { include $class . '.php'; }
$conn = mysql_connect('localhost', 'app', 'LegacyDbPass');
$result = mysql_query('SELECT 1');
$matches = ereg('^a', $value);
$parts = split(',', $value);
each($array);
$quotes = get_magic_quotes_gpc();
$enc = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
$price = money_format('%i', 10);
$first = $name{0};
$raw = $HTTP_RAW_POST_DATA;
$fn = create_function('$x', 'return $x;');
