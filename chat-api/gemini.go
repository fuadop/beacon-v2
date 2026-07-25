package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	geminiAPIBase     = "https://generativelanguage.googleapis.com/v1beta/models"
	geminiMaxTokens   = 1024
	maxToolIterations = 8
)

const systemPrompt = `You answer questions about the posture of a small network being monitored:
two Cisco routers polled via SNMP for CPU, memory, and interface metrics, plus SNMP traps
(LinkDown, ConfigChanged, etc.).

Use the provided tools to look up real data -- never guess or make up a number. If a question
needs data you don't have a tool for, say so plainly rather than speculating.

"Spiked" means a metric crossed a fixed threshold (e.g. cpu1min > 80), not a statistical
anomaly -- when asked how many times something "spiked", use query_metric with
aggregation=count_above_threshold and a reasonable threshold for that metric (80 for CPU
percentages is a sensible default unless the user specifies otherwise).

Traps cannot currently be reliably attributed to a specific device -- their recorded source IP
is masked by the network's own port-forwarding setup. If asked which device caused a trap,
say that attribution isn't reliable right now rather than guessing from context.

Give direct, concise answers. Include the actual numbers you looked up, not just a vague
characterization.`

// geminiPart is a single piece of a turn's content: plain text, a function
// call the model wants executed, or a function's result being fed back.
// Exactly one of these is set per part, mirroring Gemini's own API shape.
type geminiPart struct {
	Text             string                  `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResponse `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type geminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

// geminiFunctionDeclaration is what tools.go's toolDefinitions() builds --
// same underlying JSON-schema-shaped Parameters (type/properties/required)
// as before, just Gemini's field name (parameters) and wrapping (grouped
// under a single "tools[0].functionDeclarations" list) instead of
// Anthropic's flat per-tool list.
type geminiFunctionDeclaration struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFunctionDeclaration `json:"functionDeclarations"`
}

type geminiRequest struct {
	SystemInstruction *geminiContent  `json:"system_instruction,omitempty"`
	Contents          []geminiContent `json:"contents"`
	Tools             []geminiTool    `json:"tools,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content      geminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type geminiClient struct {
	apiKey string
	model  string
	http   *http.Client
}

func newGeminiClient(apiKey, model string) *geminiClient {
	return &geminiClient{apiKey: apiKey, model: model, http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *geminiClient) call(contents []geminiContent, tools []geminiTool) (*geminiResponse, error) {
	reqBody := geminiRequest{
		SystemInstruction: &geminiContent{Parts: []geminiPart{{Text: systemPrompt}}},
		Contents:          contents,
		Tools:             tools,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s:generateContent", geminiAPIBase, c.model)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling gemini api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed geminiResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding gemini response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("gemini api error: %s", parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if len(parsed.Candidates) == 0 {
		return nil, fmt.Errorf("gemini api returned no candidates: %s", strings.TrimSpace(string(respBody)))
	}
	return &parsed, nil
}

// runChat drives the tool-calling loop: ask the model, execute whatever
// tools it requests, feed results back, repeat until it gives a final text
// answer or maxToolIterations is hit (a hard cost/runaway-loop cap, not
// just a correctness detail -- every iteration is an API call, and while
// Gemini's free tier has no per-call charge, it's still rate-limited).
func runChat(client *geminiClient, tc toolContext, question string) (string, error) {
	contents := []geminiContent{
		{Role: "user", Parts: []geminiPart{{Text: question}}},
	}
	tools := []geminiTool{{FunctionDeclarations: toolDefinitions()}}

	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.call(contents, tools)
		if err != nil {
			return "", err
		}

		modelContent := resp.Candidates[0].Content
		modelContent.Role = "model"
		contents = append(contents, modelContent)

		var functionCalls []geminiPart
		for _, part := range modelContent.Parts {
			if part.FunctionCall != nil {
				functionCalls = append(functionCalls, part)
			}
		}

		if len(functionCalls) == 0 {
			return extractText(modelContent.Parts), nil
		}

		var responseParts []geminiPart
		for _, part := range functionCalls {
			result, err := executeTool(tc, part.FunctionCall.Name, part.FunctionCall.Args)
			responseParts = append(responseParts, buildFunctionResponsePart(part.FunctionCall.Name, result, err))
		}
		contents = append(contents, geminiContent{Role: "function", Parts: responseParts})
	}

	return "", fmt.Errorf("couldn't answer within %d tool calls -- try a narrower question", maxToolIterations)
}

// buildFunctionResponsePart wraps a tool's result (or error) into the object
// shape Gemini expects for functionResponse.response. Tool results are
// already JSON-object strings on success (see tools.go), so those unmarshal
// straight through; anything else (plain error text) gets wrapped so the
// model still sees it as a well-formed response rather than a decode failure.
func buildFunctionResponsePart(name, result string, toolErr error) geminiPart {
	var respObj map[string]any
	if toolErr != nil {
		respObj = map[string]any{"error": result}
	} else if err := json.Unmarshal([]byte(result), &respObj); err != nil {
		respObj = map[string]any{"result": result}
	}
	return geminiPart{FunctionResponse: &geminiFunctionResponse{Name: name, Response: respObj}}
}

func extractText(parts []geminiPart) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(part.Text)
	}
	return b.String()
}
