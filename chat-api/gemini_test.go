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

func TestBuildInitialContentsNoHistory(t *testing.T) {
	contents := buildInitialContents("what is the CPU usage of R1?", nil)
	if len(contents) != 1 {
		t.Fatalf("len(contents) = %d, want 1", len(contents))
	}
	if contents[0].Role != "user" || contents[0].Parts[0].Text != "what is the CPU usage of R1?" {
		t.Errorf("contents[0] = %+v", contents[0])
	}
}

func TestBuildInitialContentsWithHistory(t *testing.T) {
	history := []historyTurn{
		{Role: "user", Text: "how many routers are online?"},
		{Role: "assistant", Text: "There are 2 routers online: R1 and R2."},
	}
	contents := buildInitialContents("how did you find that?", history)

	if len(contents) != 3 {
		t.Fatalf("len(contents) = %d, want 3", len(contents))
	}
	if contents[0].Role != "user" || contents[0].Parts[0].Text != "how many routers are online?" {
		t.Errorf("contents[0] = %+v", contents[0])
	}
	if contents[1].Role != "model" || contents[1].Parts[0].Text != "There are 2 routers online: R1 and R2." {
		t.Errorf("contents[1] = %+v, want role=model", contents[1])
	}
	if contents[2].Role != "user" || contents[2].Parts[0].Text != "how did you find that?" {
		t.Errorf("contents[2] = %+v", contents[2])
	}
}

func TestBuildInitialContentsUnknownRoleMapsToModel(t *testing.T) {
	history := []historyTurn{{Role: "error", Text: "something went wrong"}}
	contents := buildInitialContents("try again", history)
	if contents[0].Role != "model" {
		t.Errorf("contents[0].Role = %q, want %q", contents[0].Role, "model")
	}
}
