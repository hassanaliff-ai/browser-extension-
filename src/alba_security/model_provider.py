"""Server-only model selection; local inference never falls back to a cloud API."""
import os
import threading
from types import SimpleNamespace

import httpx
from alba_security.reports import ReportGenerationError

_LOCAL_SLOT = threading.BoundedSemaphore(1)
LOCAL_ORIGIN = "http://127.0.0.1:11434"


def configured_model():
    provider = os.getenv("LLM_PROVIDER", "openai").strip().lower()
    return os.getenv("OLLAMA_MODEL") if provider == "ollama" else os.getenv("OPENAI_MODEL")


class LocalModelClient:
    provider_name = "ollama"

    def __init__(self):
        self.responses = self

    def create(self, *, model, instructions, input, max_output_tokens, store=False, text=None):
        if store or not model or "cloud" in model.lower():
            raise ValueError("Local inference requires a local model and no stored prompts")
        payload = {
            "model": model, "stream": False, "think": False, "keep_alive": "10m",
            "messages": [{"role": "system", "content": instructions}, {"role": "user", "content": input}],
            "options": {"temperature": 0, "num_ctx": 8192 if len(input) > 6000 else 4096,
                        "num_predict": min(max_output_tokens, 900)},
        }
        if text is not None:
            payload["format"] = text["format"]["schema"]
        if not _LOCAL_SLOT.acquire(timeout=2):
            raise ReportGenerationError("The local AI model is busy. Retry shortly; no result was saved.")
        try:
            # Ignore proxy environment settings: prompts only go to this fixed loopback endpoint.
            with httpx.Client(timeout=httpx.Timeout(150, connect=3), trust_env=False, follow_redirects=False) as client:
                with client.stream("POST", LOCAL_ORIGIN + "/api/chat", json=payload) as response:
                    response.raise_for_status()
                    parts, size = [], 0
                    for part in response.iter_bytes():
                        size += len(part)
                        if size > 65536:
                            raise ValueError("Local model response exceeded its limit")
                        parts.append(part)
                    import json
                    result = json.loads(b"".join(parts))
            message = result.get("message", {})
            if message.get("tool_calls"):
                raise ValueError("Model tools are prohibited")
            completed = result.get("done") is True and result.get("done_reason") == "stop"
            return SimpleNamespace(status="completed" if completed else "incomplete", output_text=message.get("content"))
        except httpx.ConnectError:
            raise ReportGenerationError("The local AI service is offline. Start the configured local AI runtime and retry; no result was saved.") from None
        except httpx.TimeoutException:
            raise ReportGenerationError("The local AI model timed out. Retry when it is ready; no result was saved.") from None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise ReportGenerationError("The configured local AI model is not installed. Restore it on the API computer and retry; no result was saved.") from None
            raise ReportGenerationError("The local AI service could not complete the request. Retry shortly; no result was saved.") from None
        except httpx.HTTPError:
            raise ReportGenerationError("The local AI connection was interrupted. Retry shortly; no result was saved.") from None
        finally:
            _LOCAL_SLOT.release()


def create_model_client(*, api_key=None, model=None):
    from alba_security.reports import ReportConfigurationError
    provider = os.getenv("LLM_PROVIDER", "openai").strip().lower()
    if provider not in {"openai", "ollama"}:
        raise ReportConfigurationError("LLM_PROVIDER must be openai or ollama")
    model = model or configured_model()
    if provider == "ollama":
        if not model or "cloud" in model.lower():
            raise ReportConfigurationError("OLLAMA_MODEL must name an installed local report model")
        return LocalModelClient(), model
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key or not model:
        raise ReportConfigurationError("OPENAI_API_KEY and OPENAI_MODEL are required for live LLM analysis")
    from openai import OpenAI
    return OpenAI(api_key=key, timeout=25, max_retries=0), model
