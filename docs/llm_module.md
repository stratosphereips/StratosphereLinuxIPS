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

Configuration reference:

- `enabled`: enables or disables the LLM service module.
- `default_backend`: backend alias used when a request omits `backend`.
- `worker_threads`: number of requests processed in parallel.
- `queue_size`: maximum number of queued requests in memory.
- `backends`: mapping of backend alias to backend configuration.

Per-backend options:

- `provider`: one of `ollama`, `openai`, or `anthropic`.
- `model`: default model for that backend alias.
- `base_url`: provider endpoint. If omitted, the provider default is used.
- `timeout`: HTTP timeout in seconds.
- `api_key`: optional inline API key for `openai` or `anthropic`.
- `api_key_env`: optional environment variable containing the API key.
- `api_key_file`: optional file path containing the API key.
- `anthropic_version`: optional Anthropic API version header. Default is
  `2023-06-01`.

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

## How Caller Modules Must Correlate Responses

The current design uses:

- one shared request channel: `llm_request`
- one shared response channel: `llm_response`

This means caller modules must correlate replies themselves.

Required caller pattern:

1. Subscribe to `llm_response` during module initialization.
2. Discover runtime-ready backends with
   `self.db.get_available_llm_backends()`.
3. Choose a backend alias from the returned registry.
4. Generate a unique `request_id` before publishing.
5. Keep local pending state keyed by `request_id`.
6. Publish the request to `llm_request`.
7. When reading `llm_response`, ignore any response whose `request_id` is not
   one of yours.

If multiple caller modules send requests at the same time, `request_id` is what
separates the replies. `requester` is only a human-readable label and should
not be treated as the primary routing key.

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

- `request_id`: technically optional, but caller modules should always set it.
  This is the main correlation key on the shared response channel.
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
import uuid

available = self.db.get_available_llm_backends()
backend = available["default_backend"]
if not backend:
    return

request_id = f"{self.name}-{uuid.uuid4()}"
pending_requests[request_id] = {"profileid": profileid}

request = {
    "request_id": request_id,
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
    request_id = response["request_id"]
    if request_id not in pending_requests:
        return

    context = pending_requests.pop(request_id)
    text = response["text"]
```

## Operational Notes

- The module uses one shared response channel, so requesters must match on
  `request_id`.
- Caller modules should always generate `request_id` themselves instead of
  relying on the service to create one.
- The first version is text-only.
- If the module is disabled or no valid backends are configured, it will stop
  cleanly and no request processing will occur.
- Backend selection is by runtime-ready backend alias, not only by model name.
