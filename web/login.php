<?php
/** Centinela - pantalla de acceso. */

declare(strict_types=1);
require __DIR__ . '/lib/boot.php';
require __DIR__ . '/lib/auth.php';

send_security_headers();
session_start_secure();

if (!ip_allowed()) {
    http_response_code(403);
    auth_log('denied_ip');
    exit('Acceso no permitido desde esta direccion.');
}

if (is_authenticated()) {
    header('Location: index.php');
    exit;
}

$error  = '';
$notice = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!csrf_check($_POST['csrf'] ?? null)) {
        $error = 'La sesion del formulario ha caducado. Vuelve a intentarlo.';
    } else {
        $r = auth_attempt(
            trim((string) ($_POST['user'] ?? '')),
            (string) ($_POST['pass'] ?? ''),
            (string) ($_POST['code'] ?? '')
        );
        if ($r['ok']) {
            header('Location: index.php');
            exit;
        }
        $error = $r['error'];
    }
}

$totpRequired = (bool) ($CFG['auth']['totp_required'] ?? true);
$locked = is_locked_out();
$token  = csrf_token();
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Acceso · Centinela</title>
<link rel="stylesheet" href="<?= asset('assets/app.css') ?>">
</head>
<body>
<div class="login-page">
  <div class="login-box">
    <div class="card">
      <h1><span class="brand"><span class="dot"></span></span> Centinela</h1>
      <div class="sub">Panel de seguridad de <?= h($_SERVER['HTTP_HOST'] ?? php_uname('n')) ?></div>

      <?php if ($error !== ''): ?>
        <div class="alert err" role="alert"><span aria-hidden="true">⚠</span><span><?= h($error) ?></span></div>
      <?php endif; ?>
      <?php if ($locked): ?>
        <div class="alert warn" role="alert"><span aria-hidden="true">⏱</span><span>Acceso bloqueado temporalmente por exceso de intentos fallidos.</span></div>
      <?php endif; ?>

      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($token) ?>">
        <div class="field">
          <label for="user">Usuario</label>
          <input type="text" id="user" name="user" required autofocus autocapitalize="none" autocomplete="username">
        </div>
        <div class="field">
          <label for="pass">Contrase&ntilde;a</label>
          <input type="password" id="pass" name="pass" required autocomplete="current-password">
        </div>
        <?php if ($totpRequired): ?>
        <div class="field">
          <label for="code">C&oacute;digo de verificaci&oacute;n</label>
          <input type="text" id="code" name="code" class="code" required inputmode="numeric"
                 pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code">
        </div>
        <?php endif; ?>
        <button type="submit" class="btn primary" style="width:100%;justify-content:center;padding:10px;">Entrar</button>
      </form>
    </div>
    <p class="lg-note" style="text-align:center;">
      Los intentos de acceso quedan registrados.
      <?php if (!empty($CFG['lg']['enabled']) && !empty($CFG['lg']['public'])): ?>
        <br><a href="lg.php">Looking glass p&uacute;blico</a>
      <?php endif; ?>
    </p>
  </div>
</div>
</body>
</html>
