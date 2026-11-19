<?php
// Router for the built-in server: JSON echo, a session counter in a file, 404s.
$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($p === '/missing') { http_response_code(404); echo "nope"; return true; }
$f = sys_get_temp_dir() . '/hits'; $n = (int)@file_get_contents($f) + 1; file_put_contents($f, $n, LOCK_EX);
header('Content-Type: application/json');
echo json_encode(['path' => $p, 'len' => strlen(file_get_contents('php://input')), 'sha' => substr(hash('sha256', $p), 0, 8)]);
