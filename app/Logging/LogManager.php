<?php

namespace App\Logging;

class LogManager extends \Illuminate\Log\LogManager
{
    protected function createEmergencyLogger()
    {
        $logger = parent::createEmergencyLogger();
        // Laravel bypasses configured channel taps on this fallback path.
        (new RedactSensitiveData())($logger->getLogger());
        return $logger;
    }
}
