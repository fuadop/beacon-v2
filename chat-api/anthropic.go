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
	anthropicAPIURL    = "https://api.anthropic.com/v1/messages"
	anthropicVersion   = "2023-06-01"
	anthropicModel     = "claude-sonnet-5"
	anthropicMaxTokens = 1024
	maxToolIterations  = 8
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

type contentBlock struct {
	Type      string         `json:"type"`
	Text      string         `json:"text,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     map[string]any `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   string         `json:"content,omitempty"`
	IsError   bool           `json:"is_error,omitempty"`
}

type anthropicMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

type messagesRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
}

type messagesResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Error      *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type anthropicClient struct {
	apiKey string
	http   *http.Client
}

func newAnthropicClient(apiKey string) *anthropicClient {
	return &anthropicClient{apiKey: apiKey, http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *anthropicClient) call(messages []anthropicMessage, tools []anthropicTool) (*messagesResponse, error) {
	reqBody := messagesRequest{
		Model:     anthropicModel,
		MaxTokens: anthropicMaxTokens,
		System:    systemPrompt,
		Messages:  messages,
		Tools:     tools,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling anthropic api: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed messagesResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decoding anthropic response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("anthropic api error: %s", parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return &parsed, nil
}

// runChat drives the tool-calling loop: ask the model, execute whatever
// tools it requests, feed results back, repeat until it gives a final text
// answer or maxToolIterations is hit (a hard cost/runaway-loop cap, not
// just a correctness detail -- every iteration is a paid API call).
func runChat(client *anthropicClient, tc toolContext, question string) (string, error) {
	messages := []anthropicMessage{
		{Role: "user", Content: []contentBlock{{Type: "text", Text: question}}},
	}
	tools := toolDefinitions()

	for i := 0; i < maxToolIterations; i++ {
		resp, err := client.call(messages, tools)
		if err != nil {
			return "", err
		}

		messages = append(messages, anthropicMessage{Role: "assistant", Content: resp.Content})

		if resp.StopReason != "tool_use" {
			return extractText(resp.Content), nil
		}

		var resultBlocks []contentBlock
		for _, block := range resp.Content {
			if block.Type != "tool_use" {
				continue
			}
			result, err := executeTool(tc, block.Name, block.Input)
			isErr := err != nil
			if isErr {
				result = err.Error()
			}
			resultBlocks = append(resultBlocks, contentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content:   result,
				IsError:   isErr,
			})
		}
		messages = append(messages, anthropicMessage{Role: "user", Content: resultBlocks})
	}

	return "", fmt.Errorf("couldn't answer within %d tool calls -- try a narrower question", maxToolIterations)
}

func extractText(blocks []contentBlock) string {
	var b strings.Builder
	for _, block := range blocks {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	return b.String()
}
