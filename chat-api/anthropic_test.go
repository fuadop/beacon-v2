package main

import "testing"

func TestExtractText(t *testing.T) {
	blocks := []contentBlock{
		{Type: "text", Text: "The CPU is at "},
		{Type: "tool_use", Name: "query_metric"},
		{Type: "text", Text: "40%."},
	}
	got := extractText(blocks)
	want := "The CPU is at 40%."
	if got != want {
		t.Errorf("extractText() = %q, want %q", got, want)
	}
}

func TestExtractTextNoTextBlocks(t *testing.T) {
	blocks := []contentBlock{{Type: "tool_use", Name: "list_devices"}}
	if got := extractText(blocks); got != "" {
		t.Errorf("extractText() = %q, want empty string", got)
	}
}
