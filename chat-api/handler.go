package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
)

type chatHandler struct {
	gemini      *geminiClient
	tools       toolContext
	rateLimiter *rateLimiter
	logger      *slog.Logger
}

// maxHistoryTurns caps how much prior conversation a single request can
// carry, trimmed server-side regardless of what the client sends -- every
// turn resent is extra tokens Gemini has to reprocess, and this is the one
// place in the request a caller could otherwise make arbitrarily large.
const maxHistoryTurns = 20

type historyTurn struct {
	Role string `json:"role"` // "user" or "assistant"
	Text string `json:"text"`
}

type chatRequest struct {
	Question string        `json:"question"`
	History  []historyTurn `json:"history"`
}

type chatResponse struct {
	Answer string `json:"answer"`
}

type chatErrorResponse struct {
	Error string `json:"error"`
}

func (h *chatHandler) handle(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !h.rateLimiter.allow(ip) {
		writeChatError(w, http.StatusTooManyRequests, "rate limit exceeded, try again shortly")
		return
	}

	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeChatError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Question == "" {
		writeChatError(w, http.StatusBadRequest, "question is required")
		return
	}

	history := req.History
	if len(history) > maxHistoryTurns {
		history = history[len(history)-maxHistoryTurns:]
	}

	answer, err := runChat(h.gemini, h.tools, req.Question, history, h.logger)
	if err != nil {
		h.logger.Error("chat request failed", "error", err)
		writeChatError(w, http.StatusInternalServerError, "couldn't answer that: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chatResponse{Answer: answer})
}

func writeChatError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(chatErrorResponse{Error: msg})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
