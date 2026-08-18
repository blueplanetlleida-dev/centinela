<?php
/**
 * Centinela - captcha aritmetico autocontenido.
 *
 * No depende de ningun servicio externo (ni reCAPTCHA ni similares): el reto
 * viaja firmado con HMAC, asi que no hace falta guardar estado en servidor.
 * No pretende frenar a un atacante decidido, sino a los robots triviales;
 * la defensa real del looking glass es el limite de frecuencia.
 */

declare(strict_types=1);

/** Clave de firma, derivada de un secreto persistente del servidor. */
function captcha_key(): string
{
    global $CFG;
    $f = rtrim($CFG['state_dir'] ?? '/var/lib/centinela', '/') . '/captcha.key';
    if (is_readable($f)) {
        $k = (string) file_get_contents($f);
        if (strlen($k) >= 32) {
            return $k;
        }
    }
    $k = bin2hex(random_bytes(32));
    @file_put_contents($f, $k, LOCK_EX);
    @chmod($f, 0660);
    return $k;
}

/**
 * Genera un reto.
 * @return array{question:string, token:string}
 */
function captcha_make(): array
{
    $a  = random_int(2, 9);
    $b  = random_int(2, 9);
    $op = random_int(0, 1) === 0 ? '+' : '×';
    $ans = $op === '+' ? $a + $b : $a * $b;

    $exp     = time() + 900;                 // el reto caduca en 15 minutos
    $nonce   = bin2hex(random_bytes(6));
    $payload = $exp . '.' . $nonce;
    // La respuesta NO viaja en el token, solo su firma: si formara parte del
    // texto firmado bastaria con partir la cadena por el punto para saltarse
    // la verificacion sin resolver nada.
    $sig     = hash_hmac('sha256', $ans . '.' . $payload, captcha_key());

    return [
        'question' => "¿Cuanto es {$a} {$op} {$b}?",
        'token'    => $payload . '.' . $sig,
    ];
}

/** Comprueba la respuesta contra el token firmado. */
function captcha_check(string $token, string $answer): bool
{
    $p = explode('.', $token);
    if (count($p) !== 3) {
        return false;
    }
    [$exp, $nonce, $sig] = $p;

    if (time() > (int) $exp) {
        return false;
    }
    $answer = trim($answer);
    if ($answer === '' || !ctype_digit($answer)) {
        return false;
    }
    // Se recalcula la firma con la respuesta propuesta: solo coincide si es
    // la misma que se uso al generar el reto.
    $expected = hash_hmac('sha256', $answer . '.' . $exp . '.' . $nonce, captcha_key());
    return hash_equals($expected, $sig);
}
