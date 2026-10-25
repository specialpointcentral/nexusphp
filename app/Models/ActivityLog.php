<?php

namespace App\Models;

use App\Support\SensitiveData;
use Spatie\Activitylog\Models\Activity;

class ActivityLog extends Activity
{
    protected static function booted(): void
    {
        static::saving(fn (self $activity) => $activity->redactSensitiveData());
    }

    public function redactSensitiveData(bool $historical = false): void
    {
        $activity = $this;
        $properties = $activity->properties?->all() ?? [];
        $secrets = SensitiveData::collectSecrets($properties);
        foreach ([$activity->subject, $activity->causer] as $model) {
            if ($model === null) {
                continue;
            }
            foreach ([$model->getAttributes(), $model->getRawOriginal()] as $attributes) {
                $secrets = array_merge($secrets, SensitiveData::collectSecrets($attributes));
            }
        }
        // logOnlyDirty omits an unchanged Setting.name / UserMeta.meta_key.
        // Include both names during renames so neither the old nor new secret leaks.
        $subject = $activity->subject;
        foreach (['name' => 'value', 'meta_key' => 'meta_value'] as $name => $value) {
            $names = [$properties['attributes'][$name] ?? null, $properties['old'][$name] ?? null];
            if ($subject !== null) {
                $names[] = $subject->getAttribute($name);
                $names[] = $subject->getRawOriginal($name);
            }
            $sensitive = (bool) array_filter($names, fn ($key) => is_string($key) && SensitiveData::isSensitiveKey($key));
            $indirectType = $name === 'name' ? Setting::class : UserMeta::class;
            if (!$sensitive && !($historical && $activity->subject_type === $indirectType)) {
                continue;
            }
            foreach (['attributes', 'old'] as $part) {
                if (isset($properties[$part]) && array_key_exists($value, $properties[$part])) {
                    if (!$sensitive && isset($properties[$part][$name])) {
                        continue;
                    }
                    $secrets = array_merge($secrets, SensitiveData::collectSecrets(['secret' => $properties[$part][$value]]));
                    $properties[$part][$value] = SensitiveData::REDACTED;
                }
            }
        }
        $activity->properties = collect(SensitiveData::redact($properties, $secrets));
        if (is_string($activity->description)) {
            $activity->description = SensitiveData::redactText($activity->description, $secrets);
        }
    }
}
