from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Mapping, MutableMapping, Sequence

import requests


@dataclass(frozen=True)
class RetryConfig:
    retries: int = 2
    backoff_factor: float = 0.6
    status_forcelist: Sequence[int] = (408, 429, 500, 502, 503, 504)


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
    config = retry_config or RetryConfig()
    request = session.request if session else requests.request
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
            if response.status_code in config.status_forcelist and attempt < config.retries:
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
