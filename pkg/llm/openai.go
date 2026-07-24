// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"
)

const openaiDefaultBaseURL = "https://api.openai.com/v1"

// openaiClient wraps the OpenAI REST API at a single model endpoint.
// It is unexported; callers interact with it through the Provider interface.
type openaiClient struct {
	client openai.Client
	model  string
}

func newOpenAIClient(cfg Config) (*openaiClient, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("llm: API key is required for OpenAI provider")
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = openaiDefaultBaseURL
	}
	client := openai.NewClient(
		option.WithAPIKey(cfg.APIKey),
		option.WithBaseURL(baseURL),
		option.WithRequestTimeout(cfg.Timeout),
	)
	return &openaiClient{client: client, model: cfg.Model}, nil
}

// Generate sends a single user prompt and returns the assistant's response text.
func (c *openaiClient) Generate(ctx context.Context, prompt string, opts *Options) (string, error) {
	params := openai.ChatCompletionNewParams{
		Model: shared.ChatModel(c.model),
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		},
	}
	applyOptions(&params, opts)

	resp, err := c.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return "", fmt.Errorf("openai generate: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("openai: no choices returned")
	}
	return resp.Choices[0].Message.Content, nil
}

// Chat sends a multi-turn conversation and returns the next assistant message.
func (c *openaiClient) Chat(ctx context.Context, messages []Message, opts *Options) (Message, error) {
	sdkMsgs := make([]openai.ChatCompletionMessageParamUnion, len(messages))
	for i, m := range messages {
		sdkMsgs[i] = toSDKMessage(m)
	}

	params := openai.ChatCompletionNewParams{
		Model:    shared.ChatModel(c.model),
		Messages: sdkMsgs,
	}
	applyOptions(&params, opts)

	resp, err := c.client.Chat.Completions.New(ctx, params)
	if err != nil {
		return Message{}, fmt.Errorf("openai chat: %w", err)
	}
	if len(resp.Choices) == 0 {
		return Message{}, errors.New("openai: no choices returned")
	}
	msg := resp.Choices[0].Message
	out := Message{Role: RoleAssistant, Content: msg.Content}
	for _, tc := range msg.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return out, nil
}

// Ping verifies the OpenAI endpoint is reachable by listing models.
func (c *openaiClient) Ping(ctx context.Context) error {
	_, err := c.client.Models.List(ctx)
	if err != nil {
		return fmt.Errorf("openai ping: %w", err)
	}
	return nil
}

// ModelName returns the configured model identifier.
func (c *openaiClient) ModelName() string { return c.model }

// ─── helpers ──────────────────────────────────────────────────────────────────

// applyOptions maps our provider-agnostic Options to the SDK's ChatCompletionNewParams.
func applyOptions(params *openai.ChatCompletionNewParams, opts *Options) {
	if opts == nil {
		return
	}
	if opts.Temperature != 0 {
		params.Temperature = param.NewOpt(opts.Temperature)
	}
	if opts.NumPredict > 0 {
		params.MaxTokens = param.NewOpt(int64(opts.NumPredict))
	}
	if opts.TopP != 0 {
		params.TopP = param.NewOpt(opts.TopP)
	}
	if len(opts.Stop) > 0 {
		params.Stop = openai.ChatCompletionNewParamsStopUnion{
			OfStringArray: opts.Stop,
		}
	}
	if opts.JSON {
		params.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONObject: &shared.ResponseFormatJSONObjectParam{},
		}
	}
	if len(opts.Tools) > 0 {
		params.Tools = make([]openai.ChatCompletionToolParam, len(opts.Tools))
		for i, t := range opts.Tools {
			var schema map[string]any
			if len(t.Parameters) > 0 {
				// Best-effort: a malformed schema just means no parameters are
				// advertised for this tool, not a request failure.
				_ = json.Unmarshal(t.Parameters, &schema)
			}
			params.Tools[i] = openai.ChatCompletionToolParam{
				Function: shared.FunctionDefinitionParam{
					Name:        t.Name,
					Description: param.NewOpt(t.Description),
					Parameters:  schema,
				},
			}
		}
	}
}

// toSDKMessage converts our provider-agnostic Message to the OpenAI SDK message type.
func toSDKMessage(m Message) openai.ChatCompletionMessageParamUnion {
	switch m.Role {
	case RoleSystem:
		return openai.SystemMessage(m.Content)
	case RoleUser:
		return openai.UserMessage(m.Content)
	case RoleTool:
		return openai.ToolMessage(m.Content, m.ToolCallID)
	case RoleAssistant:
		if len(m.ToolCalls) == 0 {
			return openai.AssistantMessage(m.Content)
		}
		assistant := &openai.ChatCompletionAssistantMessageParam{
			ToolCalls: make([]openai.ChatCompletionMessageToolCallParam, len(m.ToolCalls)),
		}
		if m.Content != "" {
			assistant.Content.OfString = param.NewOpt(m.Content)
		}
		for i, tc := range m.ToolCalls {
			assistant.ToolCalls[i] = openai.ChatCompletionMessageToolCallParam{
				ID: tc.ID,
				Function: openai.ChatCompletionMessageToolCallFunctionParam{
					Name:      tc.Name,
					Arguments: tc.Arguments,
				},
			}
		}
		return openai.ChatCompletionMessageParamUnion{OfAssistant: assistant}
	default:
		// default to user for unknown roles
		return openai.UserMessage(m.Content)
	}
}
