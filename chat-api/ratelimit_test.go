package main

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request should be rate limited")
	}
}

func TestRateLimiterPerIP(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("1.1.1.1") {
		t.Fatal("first request from 1.1.1.1 should be allowed")
	}
	if !rl.allow("2.2.2.2") {
		t.Fatal("first request from a different IP should be allowed independently")
	}
	if rl.allow("1.1.1.1") {
		t.Fatal("second request from 1.1.1.1 should be rate limited")
	}
}

func TestRateLimiterWindowExpires(t *testing.T) {
	rl := newRateLimiter(1, 50*time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("second request within the window should be rate limited")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Fatal("request after the window expires should be allowed again")
	}
}
