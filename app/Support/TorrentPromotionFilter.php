<?php

namespace App\Support;

use App\Models\Setting;
use App\Models\Torrent;

class TorrentPromotionFilter
{
    private ?int $since;

    public function __construct(int $days, private int $newState, private int $globalState, int $now)
    {
        $this->since = $days > 0 && isset(Torrent::$promotionTypes[$newState])
            ? $now - $days * 86400
            : null;
    }

    public static function fromSettings(): self
    {
        return new self(
            Setting::getNewTorrentPromotionTime(),
            Setting::getNewTorrentPromotionState(),
            get_global_sp_state(),
            defined('TIMENOW') ? TIMENOW : time()
        );
    }

    /**
     * Each branch is an alternative: new promotion first, then global/individual.
     * An empty branch matches everything; no branches matches nothing.
     */
    private function branches(int $state): array
    {
        if ($state === 0) {
            return [[]];
        }
        if (!isset(Torrent::$promotionTypes[$state])) {
            return [];
        }
        $branches = [];
        if ($this->since !== null && $state === $this->newState) {
            $branches[] = ['active' => true];
        }
        if ($this->globalState === Torrent::PROMOTION_NORMAL || $state === $this->globalState) {
            $fallback = [];
            if ($this->globalState === Torrent::PROMOTION_NORMAL) {
                $fallback['sp_state'] = $state;
            }
            if ($this->since !== null) {
                $fallback['active'] = false;
            }
            $branches[] = $fallback;
        }
        return $branches;
    }

    public function toSql(int $state): string
    {
        return $this->toExpression($state, 'torrents.', false);
    }

    public function toMeiliSearch(int $state): string
    {
        return $this->toExpression($state, '', true);
    }

    private function toExpression(int $state, string $prefix, bool $timestamps): string
    {
        $alternatives = [];
        foreach ($this->branches($state) as $branch) {
            if ($branch === []) {
                return '';
            }
            $conditions = [];
            if (isset($branch['sp_state'])) {
                $conditions[] = $prefix . 'sp_state = ' . $branch['sp_state'];
            }
            if (isset($branch['active'])) {
                $since = $timestamps ? (string)$this->since : "'" . date('Y-m-d H:i:s', $this->since) . "'";
                $conditions[] = $branch['active']
                    ? "{$prefix}added >= $since"
                    : "({$prefix}added IS NULL OR {$prefix}added < $since)";
            }
            $alternatives[] = '(' . implode(' AND ', $conditions) . ')';
        }
        return $alternatives ? '(' . implode(' OR ', $alternatives) . ')' : "{$prefix}id = 0";
    }

    public function toElasticsearch(int $state): array
    {
        $alternatives = [];
        foreach ($this->branches($state) as $branch) {
            if ($branch === []) {
                return ['match_all' => (object)[]];
            }
            $conditions = [];
            if (isset($branch['sp_state'])) {
                $conditions[] = ['term' => ['sp_state' => $branch['sp_state']]];
            }
            if (isset($branch['active'])) {
                $window = ['range' => ['added' => ['gte' => date('Y-m-d H:i:s', $this->since)]]];
                $conditions[] = $branch['active'] ? $window : ['bool' => ['must_not' => [$window]]];
            }
            $alternatives[] = ['bool' => ['filter' => $conditions]];
        }
        return $alternatives
            ? ['bool' => ['should' => $alternatives, 'minimum_should_match' => 1]]
            : ['match_none' => (object)[]];
    }
}
