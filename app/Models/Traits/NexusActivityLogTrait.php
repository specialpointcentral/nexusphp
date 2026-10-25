<?php

namespace App\Models\Traits;

use Spatie\Activitylog\LogOptions;
use Spatie\Activitylog\Traits\LogsActivity;
use App\Support\SensitiveData;

trait NexusActivityLogTrait
{
    use LogsActivity;
    public function getActivitylogOptions(): LogOptions
    {
        return LogOptions::defaults()
            ->logOnlyDirty()
            // Keep actor/subject/event metadata even for a credential-only change.
            ->logOnly(array_values(array_filter(
                array_keys($this->getAttributes()),
                fn ($key) => !SensitiveData::isSensitiveKey($key) && !in_array($key, $this->getHidden(), true)
            )));
    }
}
