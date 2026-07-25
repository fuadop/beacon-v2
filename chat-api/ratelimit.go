package main

import (
	"sync"
	"time"
)

// rateLimiter is a simple per-IP fixed-window limiter. Self-contained,
// in-memory, no new infra -- this exists specifically because chat-api,
// unlike every other endpoint in this project, costs real money per
// request (a paid LLM API call), so an open endpoint needs some cap against
// a runaway script or repeated accidental calls.
type rateLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	requests map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		window:   window,
		limit:    limit,
		requests: make(map[string][]time.Time),
	}
}

// allow reports whether ip is under its request limit for the current
// window, recording this request if so.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	var recent []time.Time
	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.requests[ip] = recent
		return false
	}

	rl.requests[ip] = append(recent, now)
	return true
}
