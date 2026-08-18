<?php
/** Centinela - cierre de sesion. */
declare(strict_types=1);
require __DIR__ . '/lib/boot.php';
require __DIR__ . '/lib/auth.php';
send_security_headers();
auth_logout();
header('Location: login.php');
exit;
