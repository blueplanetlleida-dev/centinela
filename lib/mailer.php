<?php
/**
 * Centinela - envio de correo.
 *
 * Usa sendmail directamente en lugar de mail() para controlar las cabeceras
 * y poder mandar multipart/alternative. En un servidor Plesk siempre hay un
 * MTA local, asi que no necesitamos configurar SMTP externo.
 */

declare(strict_types=1);

/** Localiza el binario sendmail. */
function sendmail_bin(): ?string
{
    foreach (['/usr/sbin/sendmail', '/usr/lib/sendmail', '/usr/bin/sendmail'] as $p) {
        if (is_executable($p)) {
            return $p;
        }
    }
    return null;
}

/**
 * Envia un correo multipart (texto + HTML).
 *
 * @param string|array $to  Uno o varios destinatarios.
 * @return array{ok:bool, error:string}
 */
function send_mail($to, string $subject, string $html, string $text, array $opts = []): array
{
    $bin = sendmail_bin();
    if ($bin === null) {
        return ['ok' => false, 'error' => 'no se encontro sendmail en el sistema'];
    }

    $recipients = array_values(array_filter(array_map('trim', (array) $to)));
    foreach ($recipients as $r) {
        if (!filter_var($r, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'error' => "destinatario invalido: {$r}"];
        }
    }
    if (!$recipients) {
        return ['ok' => false, 'error' => 'sin destinatarios'];
    }

    $host = $opts['host'] ?? php_uname('n');
    $from = $opts['from'] ?? ('centinela@' . $host);
    if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
        $from = 'root@' . $host;
    }
    $fromName = $opts['from_name'] ?? 'Centinela';

    $boundary = 'cent_' . bin2hex(random_bytes(12));
    // Asunto codificado para admitir acentos sin romper clientes antiguos
    $subjectEnc = '=?UTF-8?B?' . base64_encode($subject) . '?=';

    $headers = [
        'From: ' . mime_name($fromName) . ' <' . $from . '>',
        'To: ' . implode(', ', $recipients),
        'Subject: ' . $subjectEnc,
        'Date: ' . date('r'),
        'Message-ID: <' . bin2hex(random_bytes(16)) . '@' . $host . '>',
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'X-Mailer: Centinela ' . CENT_VERSION,
        'Auto-Submitted: auto-generated',
    ];
    if (!empty($opts['priority'])) {
        $headers[] = 'X-Priority: 1';
        $headers[] = 'Importance: High';
    }
    if (!empty($opts['reply_to']) && filter_var($opts['reply_to'], FILTER_VALIDATE_EMAIL)) {
        $headers[] = 'Reply-To: ' . $opts['reply_to'];
    }

    $body = "--{$boundary}\r\n"
        . "Content-Type: text/plain; charset=UTF-8\r\n"
        . "Content-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($text)) . "\r\n"
        . "--{$boundary}\r\n"
        . "Content-Type: text/html; charset=UTF-8\r\n"
        . "Content-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($html)) . "\r\n"
        . "--{$boundary}--\r\n";

    $message = implode("\r\n", $headers) . "\r\n\r\n" . $body;

    // -t lee los destinatarios de las cabeceras; -f fija el sobre (Return-Path)
    $res = run([$bin, '-t', '-i', '-f', $from], 30, $message);

    return $res['ok']
        ? ['ok' => true, 'error' => '']
        : ['ok' => false, 'error' => trim($res['err'] ?: "sendmail devolvio codigo {$res['code']}")];
}

/** Codifica un nombre para cabecera si lleva caracteres no ASCII. */
function mime_name(string $name): string
{
    return preg_match('/[^\x20-\x7E]/', $name)
        ? '=?UTF-8?B?' . base64_encode($name) . '?='
        : '"' . str_replace('"', '', $name) . '"';
}
