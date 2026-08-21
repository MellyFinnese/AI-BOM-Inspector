from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping, MutableMapping, Sequence
from urllib.parse import urlparse

import requests


@dataclass(frozen=True)
class RetryConfig:
    retries: int = 2
    backoff_factor: float = 0.6
    status_forcelist: Sequence[int] = (408, 429, 500, 502, 503, 504)


def _validate_network_target(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("Only HTTPS URLs without embedded credentials are permitted")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("Network URL must include a hostname")
    # The scanner's built-in remote metadata integration is intentionally
    # constrained to Hugging Face. Callers that need other services should
    # add an explicit, reviewed integration rather than turning this into a
    # generic outbound request primitive.
    if hostname != "huggingface.co" and not hostname.endswith(".huggingface.co"):
        raise ValueError(f"Outbound network target is not allowlisted: {hostname}")


def request_with_retry(
    method: str,
    url: str,
    *,
    timeout: float,
    retry_config: RetryConfig | None = None,
    session: requests.Session | None = None,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, str] | None = None,
    json_payload: MutableMapping[str, object] | None = None,
    data: Mapping[str, str] | None = None,
) -> requests.Response:
    _validate_network_target(url)
    config = retry_config or RetryConfig()

    if session:
        request = session.request
    else:
        method_func = getattr(requests, method.lower(), None)
        request = method_func if method_func is not None else requests.request

    last_error: Exception | None = None

    for attempt in range(config.retries + 1):
        try:
            response = request(
                method=method,
                url=url,
                timeout=timeout,
                headers=dict(headers) if headers else None,
                params=dict(params) if params else None,
                json=json_payload,
                data=dict(data) if data else None,
            )

            if (
                response.status_code in config.status_forcelist
                and attempt < config.retries
            ):
                _sleep_with_backoff(attempt, config.backoff_factor)
                continue

            return response

        except requests.RequestException as exc:
            last_error = exc

            if attempt >= config.retries:
                break

            _sleep_with_backoff(attempt, config.backoff_factor)

    if last_error:
        raise last_error

    raise RuntimeError("request_with_retry failed without a captured exception")


def _sleep_with_backoff(attempt: int, backoff_factor: float) -> None:
    delay = backoff_factor * (2**attempt)
    time.sleep(delay)
