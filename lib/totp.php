<?php
/**
 * Centinela - TOTP segun RFC 6238, sin dependencias externas.
 * Compatible con Google Authenticator, Aegis, 1Password, Bitwarden, etc.
 */

declare(strict_types=1);

const TOTP_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Genera un secreto aleatorio en base32. */
function totp_secret(int $bytes = 20): string
{
    return base32_encode(random_bytes($bytes));
}

function base32_encode(string $data): string
{
    $out = '';
    $bits = 0;
    $value = 0;
    for ($i = 0, $n = strlen($data); $i < $n; $i++) {
        $value = ($value << 8) | ord($data[$i]);
        $bits += 8;
        while ($bits >= 5) {
            $out .= TOTP_ALPHABET[($value >> ($bits - 5)) & 31];
            $bits -= 5;
        }
    }
    if ($bits > 0) {
        $out .= TOTP_ALPHABET[($value << (5 - $bits)) & 31];
    }
    return $out;
}

function base32_decode(string $b32): string
{
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $b32) ?? '');
    $out = '';
    $bits = 0;
    $value = 0;
    for ($i = 0, $n = strlen($b32); $i < $n; $i++) {
        $idx = strpos(TOTP_ALPHABET, $b32[$i]);
        if ($idx === false) {
            continue;
        }
        $value = ($value << 5) | $idx;
        $bits += 5;
        if ($bits >= 8) {
            $out .= chr(($value >> ($bits - 8)) & 255);
            $bits -= 8;
        }
    }
    return $out;
}

/** Calcula el codigo para un contador dado. */
function totp_at(string $secretB32, int $counter, int $digits = 6, string $algo = 'sha1'): string
{
    $key = base32_decode($secretB32);
    if ($key === '') {
        return '';
    }
    $bin  = pack('N*', 0, $counter);          // contador de 64 bits big-endian
    $hash = hash_hmac($algo, $bin, $key, true);
    $off  = ord($hash[strlen($hash) - 1]) & 0x0F;
    $part = ((ord($hash[$off]) & 0x7F) << 24)
          | ((ord($hash[$off + 1]) & 0xFF) << 16)
          | ((ord($hash[$off + 2]) & 0xFF) << 8)
          | (ord($hash[$off + 3]) & 0xFF);
    return str_pad((string) ($part % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

/**
 * Verifica un codigo admitiendo desfase de reloj de +-$window periodos.
 * La comparacion es en tiempo constante.
 */
function totp_verify(string $secretB32, string $code, int $window = 1, int $period = 30): bool
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== 6) {
        return false;
    }
    $counter = intdiv(time(), $period);
    $ok = false;
    for ($i = -$window; $i <= $window; $i++) {
        // Sin cortocircuito: recorremos siempre toda la ventana
        $ok = hash_equals(totp_at($secretB32, $counter + $i), $code) || $ok;
    }
    return $ok;
}

/** URI otpauth:// para dar de alta el secreto en la aplicacion movil. */
function totp_uri(string $secretB32, string $account, string $issuer = 'Centinela'): string
{
    return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
        . '?secret=' . $secretB32
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}
