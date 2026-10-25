<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null) {
    http_response_code(400);
    echo 'ID inválido';
    exit;
}

echo htmlspecialchars((string) $id, ENT_QUOTES, 'UTF-8');
