<?php

namespace App\Logging;

use App\Support\SensitiveData;
use Monolog\LogRecord;

class RedactSensitiveData
{
    public function __invoke($logger): void
    {
        $logger->pushProcessor(function (LogRecord $record): LogRecord {
            $secrets = SensitiveData::collectSecrets([$record->context, $record->extra]);
            return $record->with(
                message: SensitiveData::redactText($record->message, $secrets),
                context: SensitiveData::redact($record->context, $secrets),
                extra: SensitiveData::redact($record->extra, $secrets),
            );
        });
    }
}
