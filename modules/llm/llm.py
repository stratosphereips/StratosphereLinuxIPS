# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List

import certifi
import urllib3

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class LLMConfigurationError(Exception):
    pass


class LLMRequestError(Exception):
    pass


@dataclass
class LLMBackendConfig:
    alias: str
    provider: str
    model: str
    base_url: str
    timeout: int
    api_key: str | None = None
    anthropic_version: str = "2023-06-01"

    @classmethod
    def from_dict(cls, alias: str, data: dict):
        if not isinstance(data, dict):
            raise LLMConfigurationError(
                f"Backend {alias} must be a mapping."
            )

        provider = str(data.get("provider", "")).strip().lower()
        if provider not in {"ollama", "openai", "anthropic"}:
            raise LLMConfigurationError(
                f"Backend {alias} has unsupported provider {provider!r}."
            )

        model = str(data.get("model", "")).strip()
        if not model:
            raise LLMConfigurationError(
                f"Backend {alias} is missing a model."
            )

        timeout = data.get("timeout", 60)
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 60
        timeout = max(1, timeout)

        base_url = str(data.get("base_url", "")).strip()
        if not base_url:
            base_url = {
                "ollama": "http://127.0.0.1:11434",
                "openai": "https://api.openai.com/v1",
                "anthropic": "https://api.anthropic.com",
            }[provider]
        base_url = base_url.rstrip("/")

        api_key = cls._resolve_api_key(data)
        if provider in {"openai", "anthropic"} and not api_key:
            raise LLMConfigurationError(
                f"Backend {alias} requires an API key."
            )

        anthropic_version = str(
            data.get("anthropic_version", "2023-06-01")
        ).strip()

        return cls(
            alias=alias,
            provider=provider,
            model=model,
            base_url=base_url,
            timeout=timeout,
            api_key=api_key,
            anthropic_version=anthropic_version,
        )

    @staticmethod
    def _resolve_api_key(data: dict) -> str | None:
        api_key = data.get("api_key")
        if isinstance(api_key, str) and api_key.strip():
            return api_key.strip()

        api_key_env = data.get("api_key_env")
        if isinstance(api_key_env, str) and api_key_env.strip():
            env_value = os.environ.get(api_key_env.strip(), "").strip()
            if env_value:
                return env_value

        api_key_file = data.get("api_key_file")
        if isinstance(api_key_file, str) and api_key_file.strip():
            try:
                with open(api_key_file.strip(), "r") as f:
                    return f.read().strip() or None
            except OSError:
                return None

        return None


class LLMBackend:
    def __init__(self, config: LLMBackendConfig, pool_maxsize: int = 2):
        self.config = config
        self.http = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            maxsize=max(2, int(pool_maxsize)),
        )

    def generate(self, request: dict) -> dict:
        raise NotImplementedError

    def _request_json(
        self,
        method: str,
        url: str,
        payload: dict,
        headers: dict | None = None,
    ) -> dict:
        encoded_payload = json.dumps(payload).encode()
        try:
            response = self.http.request(
                method,
                url,
                body=encoded_payload,
                headers=headers
                or {"Content-Type": "application/json"},
                timeout=urllib3.Timeout(
                    connect=self.config.timeout,
                    read=self.config.timeout,
                ),
            )
        except urllib3.exceptions.HTTPError as exc:
            raise LLMRequestError(
                f"{self.config.alias} request failed: {exc}"
            ) from exc
        except OSError as exc:
            raise LLMRequestError(
                f"{self.config.alias} request failed: {exc}"
            ) from exc

        try:
            decoded = response.data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LLMRequestError(f"Invalid backend response: {exc}") from exc

        if response.status >= 400:
            raise LLMRequestError(
                f"{self.config.alias} returned HTTP {response.status}: "
                f"{decoded[:500]}"
            )

        try:
            return json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise LLMRequestError(
                f"Backend {self.config.alias} returned invalid JSON."
            ) from exc

    def _build_url(self, endpoint: str) -> str:
        base_url = self.config.base_url.rstrip("/")
        if endpoint.startswith("/v1/") and base_url.endswith("/v1"):
            endpoint = endpoint[3:]
        return f"{base_url}{endpoint}"

    @staticmethod
    def _normalize_usage(usage: dict | None) -> dict:
        usage = usage or {}
        return {
            "input_tokens": usage.get("prompt_tokens")
            or usage.get("input_tokens"),
            "output_tokens": usage.get("completion_tokens")
            or usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
        }

    @staticmethod
    def _join_text_blocks(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_parts.append(str(item.get("text", "")))
            return "".join(text_parts)
        return str(content or "")


class OpenAIBackend(LLMBackend):
    def generate(self, request: dict) -> dict:
        url = self._build_url("/chat/completions")
        payload = {
            "model": request.get("model") or self.config.model,
            "messages": request["messages"],
        }
        if request.get("temperature") is not None:
            payload["temperature"] = request["temperature"]
        if request.get("max_tokens") is not None:
            payload["max_tokens"] = request["max_tokens"]

        response = self._request_json(
            "POST",
            url,
            payload,
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )

        choices = response.get("choices") or []
        if not choices:
            raise LLMRequestError(
                f"Backend {self.config.alias} returned no choices."
            )

        message = choices[0].get("message", {})
        return {
            "text": self._join_text_blocks(message.get("content", "")),
            "usage": self._normalize_usage(response.get("usage")),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }


class AnthropicBackend(LLMBackend):
    def generate(self, request: dict) -> dict:
        url = self._build_url("/v1/messages")
        system_parts = []
        messages = []
        for message in request["messages"]:
            role = message["role"]
            content = message["content"]
            if role == "system":
                system_parts.append(content)
                continue
            messages.append({"role": role, "content": content})

        payload = {
            "model": request.get("model") or self.config.model,
            "messages": messages,
            "max_tokens": request.get("max_tokens") or 1024,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if request.get("temperature") is not None:
            payload["temperature"] = request["temperature"]

        response = self._request_json(
            "POST",
            url,
            payload,
            headers={
                "x-api-key": self.config.api_key,
                "anthropic-version": self.config.anthropic_version,
                "Content-Type": "application/json",
            },
        )

        content = response.get("content") or []
        return {
            "text": self._join_text_blocks(content),
            "usage": self._normalize_usage(response.get("usage")),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }


class OllamaBackend(LLMBackend):
    def generate(self, request: dict) -> dict:
        url = self._build_url("/api/chat")
        payload = {
            "model": request.get("model") or self.config.model,
            "messages": request["messages"],
            "stream": False,
        }
        options = {}
        if request.get("temperature") is not None:
            options["temperature"] = request["temperature"]
        if request.get("max_tokens") is not None:
            options["num_predict"] = request["max_tokens"]
        if options:
            payload["options"] = options

        response = self._request_json("POST", url, payload)
        message = response.get("message", {})
        usage = {
            "prompt_tokens": response.get("prompt_eval_count"),
            "completion_tokens": response.get("eval_count"),
            "total_tokens": None,
        }
        if usage["prompt_tokens"] is not None and usage["completion_tokens"] is not None:
            usage["total_tokens"] = (
                usage["prompt_tokens"] + usage["completion_tokens"]
            )
        return {
            "text": self._join_text_blocks(message.get("content", "")),
            "usage": self._normalize_usage(usage),
            "provider": self.config.provider,
            "model": response.get("model") or payload["model"],
        }


class LLM(IModule):
    name = "LLM"
    description = "Shared LLM access service for other Slips modules"
    authors = ["OpenAI Codex"]
    shutdown_grace_period_seconds = 5

    def init(self):
        self.channels = {}
        self.subscribe_to_channels()
        self.request_queue: queue.Queue = queue.Queue()
        self.worker_stop_event = threading.Event()
        self.workers: List[threading.Thread] = []
        self.backends: Dict[str, LLMBackend] = {}
        self.failed_backends: Dict[str, str] = {}
        self.default_backend = ""
        self.worker_threads = 2
        self.queue_size = 100
        self.last_request_activity = time.time()
        self.operation_log = None
        self.operation_log_path = self.get_module_specific_output_path(
            "llm.log"
        )
        self.read_configuration()

    def subscribe_to_channels(self):
        """
        Subscribe to the Redis channels used by the shared LLM service.

        Returns:
            None
        """
        if self.channels:
            return

        self.c1 = self.db.subscribe(self.db.channels.LLM_REQUEST)
        self.channels = {
            self.db.channels.LLM_REQUEST: self.c1,
        }

    def read_configuration(self):
        conf = (
            self.conf
            if hasattr(self.conf, "llm_enabled")
            else ConfigParser()
        )
        self.enabled = conf.llm_enabled()
        self.default_backend = conf.llm_default_backend().strip()
        self.worker_threads = conf.llm_worker_threads()
        self.queue_size = conf.llm_queue_size()
        self.request_queue = queue.Queue(maxsize=self.queue_size)

        backend_data = conf.llm_backends()
        for alias, data in backend_data.items():
            try:
                config = LLMBackendConfig.from_dict(alias, data)
                self.backends[alias] = self._create_backend(config)
            except LLMConfigurationError as exc:
                self.failed_backends[alias] = str(exc)

    def _create_backend(self, config: LLMBackendConfig) -> LLMBackend:
        # Keep the reusable HTTP connection pool comfortably above the
        # worker concurrency so busy runs do not spam pool-discard warnings.
        pool_maxsize = max(2, self.worker_threads * 2)
        if config.provider == "openai":
            return OpenAIBackend(config, pool_maxsize=pool_maxsize)
        if config.provider == "anthropic":
            return AnthropicBackend(config, pool_maxsize=pool_maxsize)
        return OllamaBackend(config, pool_maxsize=pool_maxsize)

    @staticmethod
    def _empty_available_backends_registry() -> dict:
        return {"default_backend": "", "backends": {}}

    def _get_available_backends_registry(self) -> dict:
        available_backends = {}
        for alias, backend in self.backends.items():
            available_backends[alias] = {
                "provider": backend.config.provider,
                "model": backend.config.model,
            }

        default_backend = self.default_backend
        if default_backend not in available_backends:
            default_backend = ""

        return {
            "default_backend": default_backend,
            "backends": available_backends,
        }

    def _store_available_backends_registry(self):
        self.db.set_available_llm_backends(
            self._get_available_backends_registry()
        )

    def _store_empty_available_backends_registry(self):
        self.db.set_available_llm_backends(
            self._empty_available_backends_registry()
        )

    def pre_main(self):
        utils.drop_root_privs_permanently()
        self._init_operation_log_file()

        if not self.enabled:
            self._store_empty_available_backends_registry()
            self._log_operation("LLM module disabled in config.")
            self.print("LLM module disabled in config.", 2, 0)
            return True

        if self.failed_backends:
            for alias, error in self.failed_backends.items():
                self._log_operation(
                    f"Skipping backend alias={alias}: {error}"
                )
                self.print(
                    f"Skipping LLM backend {alias}: {error}",
                    0,
                    1,
                )

        if not self.backends:
            self._store_empty_available_backends_registry()
            self._log_operation("No valid LLM backends configured.")
            self.print(
                "No valid LLM backends configured. Stopping LLM module.",
                0,
                1,
            )
            return True

        if self.default_backend and self.default_backend not in self.backends:
            self._log_operation(
                f"Configured default backend {self.default_backend} is unavailable."
            )
            self.print(
                f"Default LLM backend {self.default_backend} is not available.",
                0,
                1,
            )
            self.default_backend = ""

        for idx in range(self.worker_threads):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"llm_worker_{idx}",
                daemon=True,
            )
            worker.start()
            self.workers.append(worker)
            self._log_operation(
                f"Started worker thread name={worker.name}"
            )

        self._store_available_backends_registry()
        self._log_operation(
            "LLM module ready. "
            f"default_backend={self.default_backend or 'none'} "
            f"available_backends={sorted(self.backends)} "
            f"queue_size={self.queue_size} "
            f"worker_threads={self.worker_threads}"
        )
        self.print(
            f"LLM module ready with backends: {list(self.backends)}",
            2,
            0,
        )

    def should_stop(self) -> bool:
        """Wait for in-flight and follow-on LLM requests before stopping."""
        if not self.termination_event.is_set():
            return False

        if self.is_msg_received_in_any_channel() or self._has_pending_work():
            self._record_request_activity()
            return False

        return (
            time.time() - self.last_request_activity
            >= self.shutdown_grace_period_seconds
        )

    def main(self):
        if msg := self.get_msg(self.db.channels.LLM_REQUEST):
            self._enqueue_request(msg)

    def shutdown_gracefully(self):
        self._store_empty_available_backends_registry()
        self.worker_stop_event.set()
        for _ in self.workers:
            try:
                self.request_queue.put_nowait(None)
            except queue.Full:
                break
        for worker in self.workers:
            worker.join(timeout=1)
        self._log_operation("LLM module stopped.")
        if self.operation_log is not None:
            self.operation_log.close()
        return True

    def _enqueue_request(self, msg: dict):
        try:
            payload = json.loads(msg["data"])
        except json.JSONDecodeError:
            self._publish_response(
                {
                    "request_id": str(uuid.uuid4()),
                    "success": False,
                    "error": "Invalid JSON on llm_request channel.",
                    "text": "",
                }
            )
            return

        payload["request_id"] = str(
            payload.get("request_id") or uuid.uuid4()
        )

        try:
            self.request_queue.put_nowait(payload)
            self._record_request_activity()
            self._log_operation(
                "Queued llm_request "
                f"request_id={payload['request_id']} "
                f"requester={payload.get('requester', '')} "
                f"backend={payload.get('backend') or self.default_backend} "
                f"queue_size={self.request_queue.qsize()}"
            )
        except queue.Full:
            self._log_operation(
                "Rejected llm_request because the queue is full "
                f"request_id={payload['request_id']}"
            )
            self._publish_response(
                {
                    "request_id": payload["request_id"],
                    "requester": payload.get("requester"),
                    "backend": payload.get("backend"),
                    "success": False,
                    "error": "LLM request queue is full.",
                    "text": "",
                    "metadata": payload.get("metadata", {}),
                }
            )

    def _worker_loop(self):
        while not self.worker_stop_event.is_set():
            try:
                payload = self.request_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            if payload is None:
                self.request_queue.task_done()
                return

            self._record_request_activity()
            try:
                self._handle_request(payload)
            finally:
                self.request_queue.task_done()
                self._record_request_activity()

    def _handle_request(self, payload: dict):
        request_id = payload["request_id"]
        requester = payload.get("requester")
        metadata = payload.get("metadata", {})
        self._log_operation(
            "Handling llm_request "
            f"request_id={request_id} "
            f"requester={requester or ''} "
            f"backend={payload.get('backend') or self.default_backend}"
        )

        try:
            request = self._prepare_request(payload)
            backend = self.backends[request["backend"]]
            result = backend.generate(request)
            response = {
                "request_id": request_id,
                "requester": requester,
                "backend": request["backend"],
                "provider": result["provider"],
                "model": result["model"],
                "success": True,
                "text": result["text"],
                "usage": result["usage"],
                "metadata": metadata,
                "ts": time.time(),
            }
            self._log_operation(
                "Completed llm_request "
                f"request_id={request_id} "
                f"backend={request['backend']} "
                f"success=True "
                f"output_chars={len(response['text'])}"
            )
        except (LLMRequestError, KeyError, ValueError) as exc:
            response = {
                "request_id": request_id,
                "requester": requester,
                "backend": payload.get("backend"),
                "success": False,
                "error": str(exc),
                "text": "",
                "metadata": metadata,
                "ts": time.time(),
            }
            self._log_operation(
                "Completed llm_request "
                f"request_id={request_id} "
                f"backend={payload.get('backend')} "
                f"success=False error={exc}"
            )
        except Exception as exc:
            response = {
                "request_id": request_id,
                "requester": requester,
                "backend": payload.get("backend"),
                "success": False,
                "error": f"Unexpected LLM error: {exc}",
                "text": "",
                "metadata": metadata,
                "ts": time.time(),
            }
            self._log_operation(
                "Completed llm_request "
                f"request_id={request_id} "
                f"backend={payload.get('backend')} "
                f"success=False error=Unexpected LLM error: {exc}"
            )

        self._publish_response(response)

    def _prepare_request(self, payload: dict) -> dict:
        backend_name = str(
            payload.get("backend") or self.default_backend
        ).strip()
        if not backend_name:
            raise LLMRequestError("No backend specified for LLM request.")
        if backend_name not in self.backends:
            raise LLMRequestError(
                f"Unknown LLM backend requested: {backend_name}"
            )

        messages = self._normalize_messages(payload)
        request = {
            "request_id": payload["request_id"],
            "backend": backend_name,
            "messages": messages,
            "model": payload.get("model"),
            "temperature": payload.get("temperature"),
            "max_tokens": payload.get("max_tokens"),
        }
        return request

    def _normalize_messages(self, payload: dict) -> List[dict]:
        messages = payload.get("messages")
        if not messages:
            prompt = payload.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise LLMRequestError(
                    "LLM request needs either messages or prompt."
                )
            messages = [{"role": "user", "content": prompt}]

        if not isinstance(messages, list) or not messages:
            raise LLMRequestError("LLM messages must be a non-empty list.")

        normalized_messages = []
        for message in messages:
            if not isinstance(message, dict):
                raise LLMRequestError(
                    "Each LLM message must be an object."
                )
            role = str(message.get("role", "")).strip().lower()
            if role not in {"system", "user", "assistant"}:
                raise LLMRequestError(f"Invalid LLM role: {role!r}")

            content = self._normalize_message_content(message.get("content"))
            if not content:
                raise LLMRequestError("LLM message content cannot be empty.")

            normalized_messages.append(
                {"role": role, "content": content}
            )

        return normalized_messages

    @staticmethod
    def _normalize_message_content(content: Any) -> str:
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
            return "".join(parts).strip()
        if content is None:
            return ""
        return str(content).strip()

    def _publish_response(self, payload: dict):
        self._log_operation(
            "Published llm_response "
            f"request_id={payload.get('request_id')} "
            f"requester={payload.get('requester', '')} "
            f"backend={payload.get('backend')} "
            f"success={payload.get('success')}"
        )
        self.db.publish(
            self.db.channels.LLM_RESPONSE,
            json.dumps(payload),
        )

    def _has_pending_work(self) -> bool:
        """Return True while the request queue or workers still have work."""
        return self.request_queue.unfinished_tasks > 0

    def _record_request_activity(self):
        """Update the timestamp used to keep the LLM service alive."""
        self.last_request_activity = time.time()

    def _init_operation_log_file(self):
        """
        Create the per-run LLM operation log inside the module output dir.

        :return: None
        """
        utils.initialize_logfile(
            self.operation_log_path,
            getattr(self.args, "is_slips_started_by_an_update", False),
        )
        self.operation_log = open(
            self.operation_log_path,
            "a",
            encoding="utf-8",
        )

        conf = ConfigParser()
        utils.change_logfiles_ownership(
            self.operation_log_path,
            conf.get_UID(),
            conf.get_GID(),
        )

    def _log_operation(self, message: str):
        """
        Append one line to the LLM module operation log.

        :param message: Log message to append.
        :return: None
        """
        if self.operation_log is None:
            return

        timestamp = utils.get_human_readable_datetime()
        self.operation_log.write(f"{timestamp} {message}\n")
        self.operation_log.flush()
        os.fsync(self.operation_log.fileno())
