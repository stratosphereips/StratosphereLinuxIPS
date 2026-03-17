# LLM Module

The `LLM` module provides shared access to configured language model backends
for the rest of Slips.

Instead of each module managing its own API keys, URLs, and HTTP logic, they
can publish a request to Redis and read the answer from a shared response
channel.

## What It Does

The module:

1. Reads LLM backend configuration from `config/slips.yaml`
2. Connects to one or more configured providers
3. Subscribes to the Redis channel `llm_request`
4. Sends each request to the selected backend
5. Publishes the result to `llm_response`

Supported providers:

- `ollama`
- `openai`
- `anthropic`

## Configuration

Example section in `config/slips.yaml`:

```yaml
llm:
  enabled: true
  default_backend: local_qwen
  worker_threads: 2
  queue_size: 100
  backends:
    local_qwen:
      provider: ollama
      model: qwen2.5:3b
      base_url: http://127.0.0.1:11434
      timeout: 120
    openai_default:
      provider: openai
      model: gpt-4o-mini
      base_url: https://api.openai.com/v1
      api_key_env: OPENAI_API_KEY
      timeout: 60
    claude_default:
      provider: anthropic
      model: claude-sonnet-4-5
      base_url: https://api.anthropic.com
      api_key_env: ANTHROPIC_API_KEY
      timeout: 60
```

Each backend is a named connection. Other modules select it by name using the
`backend` field in the request.

## Discovery Helper

Other modules should discover available backends with:

```python
available = self.db.get_available_llm_backends()
```

This returns only runtime-ready backends:

```json
{
  "default_backend": "local_qwen",
  "backends": {
    "local_qwen": {
      "provider": "ollama",
      "model": "qwen2.5:3b"
    },
    "openai_default": {
      "provider": "openai",
      "model": "gpt-4o-mini"
    }
  }
}
```

During startup the helper may temporarily return:

```json
{
  "default_backend": "",
  "backends": {}
}
```

Caller modules should retry later if they need LLM access and the registry is
still empty.

## Redis Contract

### Request channel

Channel: `llm_request`

Minimal request:

```json
{
  "request_id": "req-123",
  "backend": "local_qwen",
  "prompt": "Summarize this alert"
}
```

Structured request:

```json
{
  "request_id": "req-456",
  "requester": "HTTP Analyzer",
  "backend": "openai_default",
  "messages": [
    {"role": "system", "content": "You are a concise security analyst."},
    {"role": "user", "content": "Analyze this flow."}
  ],
  "temperature": 0.2,
  "max_tokens": 300,
  "metadata": {"uid": "C1abc"}
}
```

Fields:

- `request_id`: optional but recommended. Generated if missing.
- `requester`: optional caller name.
- `backend`: optional if `default_backend` is set.
- `prompt`: shortcut for one user message.
- `messages`: list of text messages with roles `system`, `user`, or `assistant`.
- `model`: optional model override for the selected backend.
- `temperature`: optional sampling control.
- `max_tokens`: optional response length limit.
- `metadata`: optional passthrough object echoed back in the response.

### Response channel

Channel: `llm_response`

Success:

```json
{
  "request_id": "req-456",
  "requester": "HTTP Analyzer",
  "backend": "openai_default",
  "provider": "openai",
  "model": "gpt-4o-mini",
  "success": true,
  "text": "The flow looks like repeated beaconing with stable timing.",
  "usage": {
    "input_tokens": 120,
    "output_tokens": 40,
    "total_tokens": 160
  },
  "metadata": {"uid": "C1abc"},
  "ts": 1760000000.0
}
```

Failure:

```json
{
  "request_id": "req-999",
  "backend": "missing_backend",
  "success": false,
  "error": "Unknown LLM backend requested: missing_backend",
  "text": "",
  "metadata": {},
  "ts": 1760000000.0
}
```

## Example Integration from Another Module

Publish:

```python
import json

available = self.db.get_available_llm_backends()
backend = available["default_backend"]
if not backend:
    return

request = {
    "request_id": "req-123",
    "requester": self.name,
    "backend": backend,
    "prompt": "Summarize this alert in 2 lines.",
    "metadata": {"profileid": profileid},
}
self.db.publish("llm_request", json.dumps(request))
```

Subscribe:

```python
self.c_llm = self.db.subscribe("llm_response")
self.channels["llm_response"] = self.c_llm
```

Read:

```python
if msg := self.get_msg("llm_response"):
    response = json.loads(msg["data"])
    if response["request_id"] == "req-123":
        text = response["text"]
```

## Operational Notes

- The module uses one shared response channel, so requesters must match on
  `request_id`.
- The first version is text-only.
- If the module is disabled or no valid backends are configured, it will stop
  cleanly and no request processing will occur.
- Backend selection is by runtime-ready backend alias, not only by model name.
