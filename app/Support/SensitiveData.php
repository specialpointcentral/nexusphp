<?php

namespace App\Support;

use Illuminate\Contracts\Support\Arrayable;
use Throwable;

final class SensitiveData
{
    public const REDACTED = '[REDACTED]';

    public static function isSensitiveKey(string $key): bool
    {
        $key = preg_replace_callback('/\\\\u[0-9a-f]{4}/i', fn ($match) => json_decode('"' . $match[0] . '"') ?? '', rawurldecode($key));
        foreach (preg_split('/[.\[\]]+/', $key) as $part) {
            $part = strtolower(preg_replace('/[^a-z0-9]/i', '', $part));
            if ($part === 'downloadsupportpasskey') {
                continue;
            }
            if (preg_match('/(?:authkey|passkey|passkeyhash|passhash|passwords?|passwordhash|passwordconfirmation|secret|secretkey|signaturekey|signingkey|encryptionkey|nastoolskey|appkey|token|apikey|masterkey|privatekey|recoverycodes|twostepcode|totp|otp|response|authorization|cookies?|securepass|phpsessid|sessionid|credentials?|bindings)$/', $part)) {
                return true;
            }
        }
        return false;
    }

    public static function redact(mixed $value, array $knownSecrets = []): mixed
    {
        $secrets = [];
        $result = self::walk($value, $secrets, 0);
        return self::replaceSecretCopies($result, array_merge($knownSecrets, $secrets));
    }

    private static function replaceSecretCopies(mixed $value, array $secrets): mixed
    {
        if ($secrets === []) {
            return $value;
        }
        if (is_array($value)) {
            $redacted = [];
            foreach ($value as $key => $item) {
                $safeKey = is_string($key) ? self::redactText($key, $secrets) : $key;
                if ($safeKey !== $key && array_key_exists($safeKey, $redacted)) {
                    $safeKey .= '.' . count($redacted);
                }
                $redacted[$safeKey] = self::replaceSecretCopies($item, $secrets);
            }
            return $redacted;
        }
        return is_string($value) ? self::redactText($value, $secrets) : $value;
    }

    public static function collectSecrets(mixed $value): array
    {
        $secrets = [];
        self::walk($value, $secrets, 0);
        return array_values(array_unique($secrets));
    }

    private static function walk(mixed $value, array &$secrets, int $depth): mixed
    {
        if ($depth > 32) {
            return self::REDACTED;
        }
        if ($value instanceof Throwable) {
            return self::walk([
                'class' => $value::class,
                'code' => $value->getCode(),
                'message' => $value->getMessage(),
                'file' => $value->getFile(),
                'line' => $value->getLine(),
                // Arguments and exception objects can contain credentials.
                'trace' => array_map(fn ($frame) => array_intersect_key($frame, array_flip(['file', 'line', 'class', 'function'])), $value->getTrace()),
            ], $secrets, $depth + 1);
        }
        if ($value instanceof Arrayable) {
            $value = $value->toArray();
        } elseif (is_object($value)) {
            $value = get_object_vars($value);
        }
        if (is_array($value)) {
            $sensitiveValue = is_string($value['name'] ?? null) && self::isSensitiveKey($value['name']);
            $sensitiveMeta = is_string($value['meta_key'] ?? null) && self::isSensitiveKey($value['meta_key']);
            foreach ($value as $key => $item) {
                if (self::isSensitiveKey((string) $key) || ($key === 'value' && $sensitiveValue) || ($key === 'meta_value' && $sensitiveMeta)) {
                    self::remember($item, $secrets);
                    $value[$key] = self::REDACTED;
                } else {
                    $value[$key] = self::walk($item, $secrets, $depth + 1);
                }
            }
            return $value;
        }
        if (is_string($value)) {
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                return json_encode(self::walk($decoded, $secrets, $depth + 1), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            }
            return self::redactText($value);
        }
        return is_resource($value) ? '[resource]' : $value;
    }

    private static function remember(mixed $value, array &$secrets): void
    {
        if (is_array($value)) {
            foreach ($value as $item) {
                self::remember($item, $secrets);
            }
        } elseif (is_scalar($value) && !is_bool($value) && (string) $value !== '' && $value !== self::REDACTED) {
            $secrets[] = (string) $value;
        }
    }

    public static function redactText(string $text, array $knownSecrets = []): string
    {
        // Percent escapes are case-insensitive and can encode ordinary letters.
        // Inspect decoded copies without rewriting otherwise benign log text.
        $encoded = $text;
        for ($depth = 0; $depth < 4 && preg_match('/%[0-9a-f]{2}/i', $encoded); $depth++) {
            $encoded = rawurldecode($encoded);
            foreach ($knownSecrets as $secret) {
                if ($secret !== '' && $secret !== self::REDACTED
                    && (str_contains($encoded, $secret) || str_contains(str_replace('+', ' ', $encoded), $secret))) {
                    return self::REDACTED;
                }
            }
        }
        if ($knownSecrets !== [] && preg_match('/%[0-9a-f]{2}/i', $encoded)) {
            return self::REDACTED;
        }
        $decoded = json_decode($text, true);
        if (json_last_error() === JSON_ERROR_NONE && (is_array($decoded) || is_string($decoded))) {
            return json_encode(self::redact($decoded, $knownSecrets), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        }
        $replacements = [self::REDACTED => self::REDACTED];
        $shortSecrets = [];
        foreach ($knownSecrets as $secret) {
            if ($secret === '' || $secret === self::REDACTED) {
                continue;
            }
            if (strlen($secret) < 4) {
                $shortSecrets[] = $secret;
                continue;
            }
            foreach ([$secret, rawurlencode($secret), urlencode($secret), substr(json_encode($secret, JSON_INVALID_UTF8_SUBSTITUTE), 1, -1)] as $representation) {
                $replacements[$representation] = self::REDACTED;
            }
        }
        $text = strtr($text, $replacements);
        foreach ($shortSecrets as $secret) {
            $text = preg_replace('~(?<![A-Za-z0-9])' . preg_quote($secret, '~') . '(?![A-Za-z0-9])~', self::REDACTED, $text);
        }
        if (preg_match_all('/["\']?(?:name|meta_key)["\']?\s*[:=]\s*["\']([^"\']+)["\']/i', $text, $records)) {
            foreach ($records[1] as $name) {
                if (self::isSensitiveKey($name)) {
                    return '[Sensitive setting details redacted]';
                }
            }
        }
        // Do not attempt to parse SQL literals, positional bindings, or binary values.
        if (preg_match('/\b(?:insert\s+into|update\s+[`"\w.]+\s+set|delete\s+from|select\s+.+\s+from)\b/is', $text)) {
            return '[SQL details redacted]';
        }
        // A prefixed or malformed JSON dump has no reliable scalar-value boundary.
        // Keep its operation prefix, but omit the payload rather than unescaping it.
        if (preg_match('/\{|\[(?=\s*(?:["\'\[{0-9-]|true\b|false\b|null\b))/', $text, $fragment, PREG_OFFSET_CAPTURE)) {
            $text = substr($text, 0, $fragment[0][1]) . '[structured log details redacted]';
        }
        // Credentials can live in URL paths as well as query parameters.
        $text = preg_replace('~\b(?:https?|wss?|socks5|ftp)://[^\s<>"\']+~i', '[URL redacted]', $text);
        $text = preg_replace_callback('~/(?:[^\s<>"\']+)~', function ($match) {
            return preg_match('~(?:^|/)[a-f0-9]{32,}(?:/|\?|$)~i', rawurldecode($match[0])) ? '[URL redacted]' : $match[0];
        }, $text);
        $text = preg_replace('/\b(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie)\s*[:=]\s*[^\r\n]*/i', '[credential header redacted]', $text);
        $text = preg_replace('/\b(?:Bearer|Basic)\s+[A-Za-z0-9+\/_=.~-]+/i', '[authorization redacted]', $text);
        $pattern = <<<'REGEX'
~(?<key>["']?[A-Za-z0-9_.%\\\[\]-]+["']?)\s*(?:=>|[:=])\s*~
REGEX;
        preg_match_all($pattern, $text, $fields, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach (array_reverse($fields) as $field) {
            if (!self::isSensitiveKey(trim($field['key'][0], "\"'"))) {
                continue;
            }
            $start = $field[0][1] + strlen($field[0][0]);
            $end = strpos($text, "\n", $start);
            $text = substr($text, 0, $start) . self::REDACTED . ($end === false ? '' : substr($text, $end));
        }
        // A stringified PHP trace is not structured context; never retain call arguments.
        return preg_replace('/^(#\d+\s+[^\r\n]*?\()[^\r\n]*(\))$/m', '$1[arguments omitted]$2', $text);
    }
}
