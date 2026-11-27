# LLM Module

The `LLM` module is a shared service for other Slips modules.

It reads configured backend connections from `config/slips.yaml`, listens for
requests on the Redis channel `llm_request`, sends the prompt to the selected
backend, and publishes the reply on `llm_response`.

## Supported providers

- `ollama`
- `llama_cpp` (local llama.cpp server with an OpenAI-compatible endpoint)
- `openai`
- `anthropic`

## Configuration

Example:

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
    slips_summary_q4:
      provider: llama_cpp
      model: slips-summary-q4
      base_url: http://127.0.0.1:8080/v1
      timeout: 300
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

- `enabled`: enables or disables the shared LLM service module.
- `default_backend`: backend alias used when a request does not include
  `backend`.
- `worker_threads`: number of requests the module can process in parallel.
- `queue_size`: maximum number of pending requests held in memory.
- `backends`: mapping of backend alias to backend connection settings.

Per-backend options:

- `provider`: one of `ollama`, `llama_cpp`, `openai`, or `anthropic`.
- `model`: default model used by that backend alias.
- `base_url`: provider endpoint. If omitted, the module uses the provider
  default.
- `timeout`: HTTP timeout in seconds.
- `api_key`: optional inline API key for `openai` or `anthropic`.
- `api_key_env`: optional environment variable name holding the API key.
- `api_key_file`: optional file path containing the API key.
- `anthropic_version`: optional Anthropic API version header. Default is
  `2023-06-01`.

`llama_cpp` requires a loopback HTTP endpoint and does not require an API key.
The server must be started separately before Slips sends requests. The
`slips_summary_q4` alias selects the locally hosted summary model; keep the
general LLM backend for regex generation and other tasks.

On macOS, install `llama.cpp` with `brew install llama.cpp`. From the repository
root, download the 505 MiB Q4_K_M model into a sibling directory and start the
local server:

```sh
mkdir -p ../slips-models
curl -fL https://huggingface.co/stratosphere/qwen3.5-0.8b-slips-immune-summarization/resolve/main/gguf/qwen3.5-0.8b-slips-immune-summarization-Q4_K_M.gguf -o ../slips-models/qwen3.5-0.8b-slips-immune-summarization-Q4_K_M.gguf
llama-server -m ../slips-models/qwen3.5-0.8b-slips-immune-summarization-Q4_K_M.gguf -c 8192 -t 4 -np 1 -fa off --jinja -ngl 99 -a slips-summary-q4 --host 127.0.0.1 --port 8080
```

On Linux or Raspberry Pi, install a current llama.cpp build for that platform
and use the same model and server options. Omit `-ngl 99` if GPU offloading is
unavailable. The model is trained for incident summaries, not general regex
generation. See the [model card](https://huggingface.co/stratosphere/qwen3.5-0.8b-slips-immune-summarization)
and [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/tree/master/tools/server).

Backend aliases are the names that caller modules use in the request field
`backend`. The alias is the stable selector. The `model` field inside a request
is only an optional override for that chosen backend.

## Saved responses

Requests with `"cache": true` reuse a successful response when the normalized
messages, backend, model, temperature, and token limit match. Slips saves these
responses in `permanent/databases/llm_responses.sqlite` (or the configured
`parameters.permanent_dir`). This survives Slips restarts. The cache holds at
most 50,000 responses or 256 MiB of response data and removes the oldest when
full. It stores generated text, not the input prompt. Failed and empty replies
are never saved. A changed prompt or model gets a new response.

Alert summaries and on-click evidence explanations opt in. Regex generation
does not, because each request must be able to produce a new pattern. The web
can retrieve a saved explanation from this database after its seven-day Redis
result expires.

## Implementation Layout

`llm.py` contains the `LLM` service class that implements `IModule`. Backend
support is split across these files:

- `llm_backend_config.py`: backend configuration validation.
- `llm_backend.py`: shared HTTP and response helpers.
- `openai_backend_mixin.py`: `MixinOpenAIBackend`.
- `anthropic_backend_mixin.py`: `MixinAnthropicBackend`.
- `ollama_backend_mixin.py`: `MixinOllamaBackend`.
- `llm_errors.py`: shared LLM exceptions.

Provider-specific behavior should live in a `_mixin.py` file and use a class
name prefixed with `Mixin`.

## Request channel

Channel: `llm_request`

Minimal request:

```json
{
  "request_id": "req-123",
  "backend": "local_qwen",
  "prompt": "Summarize this alert"
}
```

Request with explicit messages:

```json
{
  "request_id": "req-456",
  "requester": "Flow Alerts",
  "backend": "openai_default",
  "messages": [
    {"role": "system", "content": "You are a concise security analyst."},
    {"role": "user", "content": "Explain this incident."}
  ],
  "temperature": 0.2,
  "max_tokens": 300,
  "metadata": {"profileid": "profile_192.168.1.10"}
}
```

Fields:

- `request_id`: technically optional, but caller modules should always set it.
  This is the primary correlation key on the shared response channel.
- `requester`: optional module name for easier correlation.
- `backend`: optional if `default_backend` is configured.
- `prompt`: shortcut for a single user message.
- `messages`: list of text messages using `system`, `user`, or `assistant`.
- `model`: optional override of the configured model for that backend.
- `temperature`: optional float.
- `max_tokens`: optional integer.
- `metadata`: optional passthrough object returned unchanged in the response.

## Discovery helper

Caller modules can discover the runtime-ready backends using:

```python
available = self.db.get_available_llm_backends()
```

The returned shape is:

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

If the LLM module is disabled, still starting, or no backend is runtime-ready
yet, the helper returns:

```json
{
  "default_backend": "",
  "backends": {}
}
```

Caller modules should retry later instead of treating an empty result as a
permanent failure.

## How Caller Modules Should Use It

This module uses one shared request channel and one shared response channel for
all of Slips.

That means caller modules must follow this pattern:

1. Subscribe to `llm_response` during module initialization.
2. Call `self.db.get_available_llm_backends()` before choosing a backend.
3. Pick a backend alias from `available["backends"]` or use
   `available["default_backend"]`.
4. Generate a unique `request_id` before publishing.
5. Store local context keyed by `request_id` if the response must be matched
   back to a flow, profile, or alert.
6. Publish the request to `llm_request`.
7. Read from `llm_response` and ignore responses whose `request_id` is not one
   of yours.

If two modules send requests at the same time, they separate replies by
matching on `request_id`. `requester` is only a human-readable label. It is not
the primary routing key.

Recommended pattern:

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

Response handling:

```python
if msg := self.get_msg("llm_response"):
    response = json.loads(msg["data"])
    request_id = response["request_id"]
    if request_id not in pending_requests:
        return

    context = pending_requests.pop(request_id)
    text = response["text"]
```

Do not rely on the service to generate `request_id` for you. If the caller does
not generate it first, the caller cannot reliably match the reply later.

## Response channel

Channel: `llm_response`

Success response:

```json
{
  "request_id": "req-456",
  "requester": "Flow Alerts",
  "backend": "openai_default",
  "provider": "openai",
  "model": "gpt-4o-mini",
  "success": true,
  "text": "This alert shows repeated outbound connections...",
  "usage": {
    "input_tokens": 123,
    "output_tokens": 57,
    "total_tokens": 180
  },
  "metadata": {"profileid": "profile_192.168.1.10"},
  "ts": 1760000000.0
}
```

Error response:

```json
{
  "request_id": "req-789",
  "backend": "missing_backend",
  "success": false,
  "error": "Unknown LLM backend requested: missing_backend",
  "text": "",
  "metadata": {},
  "ts": 1760000000.0
}
```

## Notes

- The module uses one shared response channel, so requesters must correlate
  responses using `request_id`.
- Version 1 is text-only. It accepts plain string prompts and message content.
- Other modules can choose the backend per request by setting `backend`.
- The runtime discovery helper exposes only runtime-ready backends, not every
  configured backend.
