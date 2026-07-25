package main

import "testing"

func TestSQLQuoteEscapesSingleQuotes(t *testing.T) {
	got := sqlQuote("O'Brien")
	want := "'O''Brien'"
	if got != want {
		t.Errorf("sqlQuote() = %q, want %q", got, want)
	}
}

func TestSQLQuotePlain(t *testing.T) {
	got := sqlQuote("172.16.154.63")
	want := "'172.16.154.63'"
	if got != want {
		t.Errorf("sqlQuote() = %q, want %q", got, want)
	}
}
