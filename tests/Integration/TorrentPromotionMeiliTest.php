<?php

namespace Tests\Integration;

use App\Support\TorrentPromotionFilter;
use Meilisearch\Client;
use PHPUnit\Framework\TestCase;
use Tests\Unit\TorrentPromotionFilterTest;

class TorrentPromotionMeiliTest extends TestCase
{
    public function testPromotionFiltersAgainstMeilisearch(): void
    {
        $url = getenv('NEXUS_TEST_MEILI_URL');
        if (!$url) {
            self::markTestSkipped('Set NEXUS_TEST_MEILI_URL to an isolated test Meilisearch service.');
        }
        $client = new Client($url);
        $indexName = 'promotion_test_' . bin2hex(random_bytes(6));
        $previousTimezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        try {
            $task = $client->createIndex($indexName, ['primaryKey' => 'id']);
            $client->waitForTask($task['taskUid']);
            $index = $client->index($indexName);
            $task = $index->updateSettings(['filterableAttributes' => ['id', 'sp_state', 'added'], 'sortableAttributes' => ['id']]);
            $client->waitForTask($task['taskUid']);
            $documents = [];
            foreach ([
                [1, 1, '2026-10-25 06:00:00'],
                [2, 2, '2026-10-25 06:00:00'],
                [3, 1, '2026-10-23 12:00:00'],
                [4, 2, '2026-10-23 12:00:00'],
                [5, 1, '2026-10-24 12:00:00'],
                [6, 1, '2026-10-24 11:59:59'],
                [7, 1, null],
            ] as [$id, $state, $added]) {
                $documents[] = ['id' => $id, 'sp_state' => $state, 'added' => $added === null ? null : strtotime($added)];
            }
            $task = $index->addDocuments($documents);
            $client->waitForTask($task['taskUid']);
            foreach (TorrentPromotionFilterTest::promotionFilters() as $name => [$days, $newState, $globalState, $requested, $expected]) {
                $filter = new TorrentPromotionFilter($days, $newState, $globalState, strtotime('2026-10-25 12:00:00'));
                $options = ['sort' => ['id:asc']];
                $expression = $filter->toMeiliSearch($requested);
                if ($expression !== '') {
                    $options['filter'] = [$expression];
                }
                $result = $index->search('', $options);
                self::assertSame($expected, array_column($result->getHits(), 'id'), $name);
            }
        } finally {
            date_default_timezone_set($previousTimezone);
            $task = $client->deleteIndex($indexName);
            $client->waitForTask($task['taskUid']);
        }
    }
}
