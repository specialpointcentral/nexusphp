<?php

namespace Tests\Unit;

use App\Support\TorrentPromotionFilter;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class TorrentPromotionFilterTest extends TestCase
{
    #[DataProvider('promotionFilters')]
    public function testSqlAndTimestampFiltersMatchEffectivePromotions(int $days, int $newState, int $globalState, int $requested, array $expected): void
    {
        $previousTimezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        try {
            $filter = new TorrentPromotionFilter($days, $newState, $globalState, strtotime('2026-10-25 12:00:00'));
            foreach ([false, true] as $timestamps) {
                $db = new PDO('sqlite::memory:');
                $db->exec('CREATE TABLE torrents (id INTEGER, sp_state INTEGER, added ' . ($timestamps ? 'INTEGER' : 'TEXT') . ')');
                $insert = $db->prepare('INSERT INTO torrents VALUES (?, ?, ?)');
                foreach ([
                    [1, 1, '2026-10-25 06:00:00'],
                    [2, 2, '2026-10-25 06:00:00'],
                    [3, 1, '2026-10-23 12:00:00'],
                    [4, 2, '2026-10-23 12:00:00'],
                    [5, 1, '2026-10-24 12:00:00'], // Inclusive expiry boundary.
                    [6, 1, '2026-10-24 11:59:59'],
                    [7, 1, null],
                ] as [$id, $state, $added]) {
                    $insert->execute([$id, $state, $timestamps && $added !== null ? strtotime($added) : $added]);
                }
                $where = $timestamps ? $filter->toMeiliSearch($requested) : $filter->toSql($requested);
                $query = 'SELECT id FROM torrents' . ($where === '' ? '' : ' WHERE ' . $where) . ' ORDER BY id';
                self::assertSame($expected, $db->query($query)->fetchAll(PDO::FETCH_COLUMN), $query);
            }
        } finally {
            date_default_timezone_set($previousTimezone);
        }
    }

    public static function promotionFilters(): array
    {
        return [
            'new free plus old individual free' => [1, 2, 1, 2, [1, 2, 4, 5]],
            'normal excludes new free' => [1, 2, 1, 1, [3, 6, 7]],
            'new double upload overrides stored free' => [1, 3, 1, 2, [4]],
            'global free excludes new double upload' => [1, 3, 2, 2, [3, 4, 6, 7]],
            'new promotion overrides global free' => [1, 3, 2, 3, [1, 2, 5]],
            'no normal during global free' => [1, 3, 2, 1, []],
            'same global and new promotion' => [1, 2, 2, 2, [1, 2, 3, 4, 5, 6, 7]],
            'disabled rule preserves individual' => [0, 2, 1, 2, [2, 4]],
            'invalid rule preserves individual' => [1, 99, 1, 2, [2, 4]],
            'disabled rule with global promotion' => [0, 2, 2, 1, []],
            'all does not filter' => [1, 2, 1, 0, [1, 2, 3, 4, 5, 6, 7]],
        ];
    }

    public function testElasticsearchQueryIncludesWindowAndFallback(): void
    {
        $previousTimezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        try {
            $filter = new TorrentPromotionFilter(1, 2, 1, strtotime('2026-10-25 12:00:00'));
            $window = ['range' => ['added' => ['gte' => '2026-10-24 12:00:00']]];
            self::assertSame(['bool' => ['should' => [
                ['bool' => ['filter' => [$window]]],
                ['bool' => ['filter' => [
                    ['term' => ['sp_state' => 2]],
                    ['bool' => ['must_not' => [$window]]],
                ]]],
            ], 'minimum_should_match' => 1]], $filter->toElasticsearch(2));
        } finally {
            date_default_timezone_set($previousTimezone);
        }
    }
}
