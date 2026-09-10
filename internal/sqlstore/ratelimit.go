package sqlstore

import (
	"context"
	"time"
)

// CountAttempt implements store.RateLimitCounter.
//
// One statement counts the attempt, so two instances cannot both read the same
// count. The statement needs no lock, so it is safe behind a transaction
// pooler.
func (s *Store) CountAttempt(ctx context.Context, key string, window time.Duration, now time.Time) (int, time.Time, error) {
	cutoff := now.Add(-window)
	table := s.n.RateLimits
	query := "INSERT INTO " + table + " (key, window_start, count) VALUES (?, ?, 1) " +
		"ON CONFLICT (key) DO UPDATE SET " +
		"count = CASE WHEN " + table + ".window_start <= ? THEN 1 ELSE " + table + ".count + 1 END, " +
		"window_start = CASE WHEN " + table + ".window_start <= ? THEN ? ELSE " + table + ".window_start END " +
		"RETURNING count, window_start"
	row := s.queryRow(ctx, query, key, s.bindTime(now), s.bindTime(cutoff), s.bindTime(cutoff), s.bindTime(now))
	var count int
	var start time.Time
	if err := row.Scan(&count, timeScan{&start}); err != nil {
		return 0, time.Time{}, s.mapErr(err)
	}
	return count, start, nil
}

// CleanupRateLimits implements store.RateLimitCounter.
func (s *Store) CleanupRateLimits(ctx context.Context, before time.Time) (int, error) {
	res, err := s.exec(ctx, "DELETE FROM "+s.n.RateLimits+" WHERE window_start <= ?", s.bindTime(before))
	if err != nil {
		return 0, s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
