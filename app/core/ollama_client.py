"""
ollama_client.py - Ollama Local LLM Client

Provides a clean interface to the Ollama REST API for offline AI-powered
log analysis. Designed for resilience — gracefully degrades if Ollama
is not available.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Iterator, Optional

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults (overridable via environment variables)
# ---------------------------------------------------------------------------

DEFAULT_OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT", "120"))
DEFAULT_MAX_TOKENS = int(os.getenv("OLLAMA_MAX_TOKENS", "2048"))
DEFAULT_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OllamaUnavailableError(RuntimeError):
    """Raised when the Ollama service cannot be reached."""


class OllamaModelNotFoundError(RuntimeError):
    """Raised when the requested model is not installed."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OllamaClient:
    """
    Wrapper around the Ollama /api/chat and /api/generate REST endpoints.

    Usage
    -----
    ::

        client = OllamaClient(model="mistral")
        response = client.chat(system_prompt="You are...", user_prompt="Analyse...")
        print(response)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    # Health / connectivity
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if Ollama is running and reachable."""
        try:
            resp = self._session.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except (ConnectionError, Timeout):
            return False

    def list_models(self) -> list[str]:
        """Return a list of locally available model names."""
        try:
            resp = self._session.get(f"{self.base_url}/api/tags", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception as exc:
            logger.warning("Could not list Ollama models: %s", exc)
            return []

    def model_is_available(self) -> bool:
        """Return True if the configured model is downloaded."""
        models = self.list_models()
        return any(self.model in m for m in models)

    # ------------------------------------------------------------------
    # Core generation methods
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        system: str = "",
        stream: bool = False,
    ) -> str:
        """
        Call the /api/generate endpoint (single-turn generation).

        Parameters
        ----------
        prompt:
            The user prompt text.
        system:
            Optional system instruction prepended to the conversation.
        stream:
            If True, streams and concatenates the response (for long outputs).

        Returns
        -------
        str
            The model's full response text.

        Raises
        ------
        OllamaUnavailableError
            If the Ollama server cannot be reached.
        OllamaModelNotFoundError
            If the requested model is not installed.
        """
        if not self.is_available():
            raise OllamaUnavailableError(
                f"Ollama server not reachable at {self.base_url}. "
                "Please start Ollama with: `ollama serve`"
            )

        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        if system:
            payload["system"] = system

        try:
            if stream:
                return self._stream_generate(payload)
            resp = self._session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            self._handle_response_errors(resp)
            data = resp.json()
            return data.get("response", "").strip()

        except OllamaUnavailableError:
            raise
        except OllamaModelNotFoundError:
            raise
        except Timeout:
            raise OllamaUnavailableError(
                f"Ollama request timed out after {self.timeout}s. "
                "Try a smaller model or increase OLLAMA_TIMEOUT."
            )
        except RequestException as exc:
            raise OllamaUnavailableError(f"Ollama request failed: {exc}") from exc

    def chat(
        self,
        user_prompt: str,
        system_prompt: str = "",
        history: Optional[list[dict]] = None,
    ) -> str:
        """
        Call the /api/chat endpoint (multi-turn conversation).

        Parameters
        ----------
        user_prompt:
            The current user message.
        system_prompt:
            System role instructions.
        history:
            Optional list of prior messages: [{"role": ..., "content": ...}].

        Returns
        -------
        str
            The assistant's response text.
        """
        if not self.is_available():
            raise OllamaUnavailableError(
                f"Ollama server not reachable at {self.base_url}. "
                "Please start Ollama with: `ollama serve`"
            )

        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": user_prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }

        try:
            resp = self._session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            self._handle_response_errors(resp)
            data = resp.json()
            return data.get("message", {}).get("content", "").strip()

        except OllamaUnavailableError:
            raise
        except Timeout:
            raise OllamaUnavailableError(
                f"Ollama chat timed out after {self.timeout}s."
            )
        except RequestException as exc:
            raise OllamaUnavailableError(f"Ollama chat request failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _stream_generate(self, payload: dict) -> str:
        """Stream a generation response and concatenate all tokens."""
        full_response = []
        with self._session.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=self.timeout,
            stream=True,
        ) as resp:
            self._handle_response_errors(resp)
            for line in resp.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        full_response.append(chunk.get("response", ""))
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
        return "".join(full_response).strip()

    def _handle_response_errors(self, resp: requests.Response) -> None:
        """Raise appropriate exceptions for non-200 responses."""
        if resp.status_code == 404:
            raise OllamaModelNotFoundError(
                f"Model '{self.model}' not found in Ollama. "
                f"Install it with: `ollama pull {self.model}`"
            )
        if resp.status_code != 200:
            raise OllamaUnavailableError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
            )


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def get_ai_analysis(
    user_prompt: str,
    system_prompt: str = "",
    model: str = DEFAULT_MODEL,
    fallback_on_error: bool = True,
) -> tuple[str, bool]:
    """
    Convenience wrapper for one-shot AI analysis.

    Parameters
    ----------
    user_prompt:
        The analysis prompt.
    system_prompt:
        System instruction for the analyst persona.
    model:
        Ollama model to use.
    fallback_on_error:
        If True, return a degraded fallback message instead of raising.

    Returns
    -------
    tuple[str, bool]
        (response_text, ai_was_available)
    """
    client = OllamaClient(model=model)

    try:
        start = time.monotonic()
        response = client.chat(
            user_prompt=user_prompt,
            system_prompt=system_prompt,
        )
        elapsed = time.monotonic() - start
        logger.info("AI analysis completed in %.1fs using model '%s'", elapsed, model)
        return response, True

    except (OllamaUnavailableError, OllamaModelNotFoundError) as exc:
        logger.warning("AI analysis unavailable: %s", exc)
        if fallback_on_error:
            fallback = (
                "⚠️  AI analysis unavailable (Ollama not running or model not installed).\n\n"
                "Rule-based detection results are still valid and complete.\n\n"
                f"To enable AI analysis:\n"
                f"  1. Install Ollama: https://ollama.ai\n"
                f"  2. Start the service: `ollama serve`\n"
                f"  3. Pull the model: `ollama pull {model}`\n"
                f"  4. Re-run the analysis."
            )
            return fallback, False
        raise
