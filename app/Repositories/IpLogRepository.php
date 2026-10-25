<?php

namespace App\Repositories;

use App\Models\IpLog;
use Carbon\Carbon;
use Nexus\Database\NexusDB;

class IpLogRepository extends BaseRepository
{
    const CACHE_KEY_PREFIX = 'nexus_ip_logs';

    private const CACHE_TIME = 72 * 3600;

    public static function saveToCache($userId, $uri = null, $ipArr = null): void
    {
        if (!is_numeric($userId) || $userId <= 0) {
            do_log("invalid userId: $userId", "error");
            return;
        }
        $redis = NexusDB::redis();
        $uri = self::safeEndpoint($uri ?? ($_SERVER['REQUEST_URI'] ?? ''));
        if (is_null($ipArr)) {
            $ipArr = [getip()];
        }
        $key = sprintf("%s:%s", self::CACHE_KEY_PREFIX, date('Y-m-d-H'));
        foreach ($ipArr as $ip) {
            $field = sprintf("%s|%s|%s", $userId, $ip, $uri);
            $result = $redis->hincrby($key, $field, 1);
            do_log("success hincrby $key $field, result: $result", "debug");
            if ($result === 1) {
                $redis->expire($key, self::CACHE_TIME);
            }
        }
    }

    public static function saveToDB(): void
    {
        $beginTimestamp = microtime(true);
        $redis = NexusDB::redis();
        $begin = Carbon::now()->subSeconds(self::CACHE_TIME);
        $end = Carbon::now()->subHours(1);
        $interval =\DateInterval::createFromDateString("1 hour");
        $period = new \DatePeriod($begin->clone(), $interval, $end);
        $size = 2000;
        do_log(sprintf("begin: %s, end: %s, size: %s", $begin->toDateTimeString(), $end->toDateTimeString(), $size));
        $redis->setOption(\Redis::OPT_SCAN, \Redis::SCAN_RETRY);
        foreach ($period as $dt) {
            $key = sprintf("%s:%s", self::CACHE_KEY_PREFIX, $dt->format('Y-m-d-H'));
            if (!$redis->exists($key)) {
                do_log("key: $key not found", "debug");
                continue;
            }
            if ($redis->hlen($key) == 0) {
                do_log("key: $key length = 0", "debug");
                $redis->unlink($key);
            }
            do_log("handing key: $key");
            //遍历hash
            $it = NULL;
            while($arr_keys = $redis->hScan($key, $it, "*", $size)) {
                $insert = [];
                foreach ($arr_keys as $field => $value) {
                    list($userId, $ip, $uri) = explode("|", $field);
                    $insert[] = [
                        'userid' => $userId,
                        'ip' => $ip,
                        'uri' => self::safeEndpoint($uri),
                        'access' => date("Y-m-d H:i:s"),
                        'count' => intval($value),
                    ];
                }
                if (!empty($insert)) {
                    IpLog::query()->insert($insert);
                }
                do_log("key: $key, it: $it, count: " . count($insert));
            }
            $redis->unlink($key);
            do_log("handle key: $key done!");
        }
        do_log(sprintf("all done! cost time: %.3f sec.", microtime(true) - $beginTimestamp));
    }

    private static function safeEndpoint(string $uri): string
    {
        $path = parse_url($uri, PHP_URL_PATH);
        // Preserve real legacy endpoint names, never dynamic path credentials.
        // Apply on both sides of the buffer so older entries cannot leak on flush.
        if (is_string($path) && preg_match('~^/[A-Za-z0-9_-]+[.]php$~D', $path)
            && is_file(dirname(__DIR__, 2) . '/public' . $path)) {
            return $path;
        }
        return '/[dynamic-route]';
    }

}
