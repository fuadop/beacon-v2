package main

import (
	"errors"
	"testing"
)

func TestExtractText(t *testing.T) {
	parts := []geminiPart{
		{Text: "The CPU is at "},
		{FunctionCall: &geminiFunctionCall{Name: "query_metric"}},
		{Text: "40%."},
	}
	got := extractText(parts)
	want := "The CPU is at 40%."
	if got != want {
		t.Errorf("extractText() = %q, want %q", got, want)
	}
}

func TestExtractTextNoTextParts(t *testing.T) {
	parts := []geminiPart{{FunctionCall: &geminiFunctionCall{Name: "list_devices"}}}
	if got := extractText(parts); got != "" {
		t.Errorf("extractText() = %q, want empty string", got)
	}
}

func TestBuildFunctionResponsePartSuccess(t *testing.T) {
	part := buildFunctionResponsePart("list_devices", `{"count":2}`, nil)
	if part.FunctionResponse == nil {
		t.Fatal("expected a FunctionResponse")
	}
	if part.FunctionResponse.Response["count"] != 2.0 {
		t.Errorf("response[count] = %v, want 2", part.FunctionResponse.Response["count"])
	}
}

func TestBuildFunctionResponsePartError(t *testing.T) {
	part := buildFunctionResponsePart("query_metric", "unknown table", errors.New("unknown table"))
	if part.FunctionResponse.Response["error"] != "unknown table" {
		t.Errorf("response[error] = %v, want %q", part.FunctionResponse.Response["error"], "unknown table")
	}
}

func TestBuildFunctionResponsePartNonJSONResult(t *testing.T) {
	part := buildFunctionResponsePart("query_metric", "plain text result", nil)
	if part.FunctionResponse.Response["result"] != "plain text result" {
		t.Errorf("response[result] = %v, want %q", part.FunctionResponse.Response["result"], "plain text result")
	}
}
