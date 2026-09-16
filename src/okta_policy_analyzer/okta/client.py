"""Minimal, dependency-light Okta Management API client.

Only read-only GET access is needed by the analyzer. The client handles:

* authentication with an SSWS API token or an OAuth 2.0 bearer token,
* cursor pagination via the ``Link: <...>; rel="next"`` response header,
* rate limiting (HTTP 429 and pre-emptive back-off from ``X-Rate-Limit-*`` headers),
* transient error retries with exponential back-off.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

log = logging.getLogger(__name__)

_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


class OktaAPIError(RuntimeError):
    """Raised when the Okta API returns a non-retryable error."""

    def __init__(self, status: int, url: str, body: Any):
        self.status = status
        self.url = url
        self.body = body
        summary = body.get("errorSummary") if isinstance(body, dict) else body
        super().__init__(f"Okta API error {status} for {url}: {summary}")


def parse_next_link(link_header: str | None) -> str | None:
    """Return the URL of the ``rel="next"`` link, if any."""
    if not link_header:
        return None
    m = _LINK_NEXT_RE.search(link_header)
    return m.group(1) if m else None


class OktaClient:
    """Read-only client for one Okta org.

    Parameters
    ----------
    org_url:
        e.g. ``https://example.okta.com`` (no trailing slash needed).
    api_token:
        SSWS API token. Mutually exclusive with ``bearer_token``.
    bearer_token:
        OAuth 2.0 access token (``Authorization: Bearer``), e.g. from the *OAuth 2.0 for Okta* flow
        with the ``okta.*.read`` scopes.
    transport:
        Optional ``httpx`` transport (used by tests to mock the API).
    sleep:
        Sleep function, injectable for tests.
    """

    def __init__(
        self,
        org_url: str,
        api_token: str | None = None,
        bearer_token: str | None = None,
        *,
        timeout: float = 30.0,
        max_retries: int = 5,
        page_limit: int = 200,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        min_remaining: int = 2,
    ):
        if bool(api_token) == bool(bearer_token):
            raise ValueError("exactly one of api_token or bearer_token must be given")
        self.org_url = org_url.rstrip("/")
        if not self.org_url.startswith("https://"):
            raise ValueError("org_url must start with https://")
        auth = f"SSWS {api_token}" if api_token else f"Bearer {bearer_token}"
        self._http = httpx.Client(
            base_url=self.org_url,
            headers={
                "Authorization": auth,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "okta-policy-analyzer",
            },
            timeout=timeout,
            transport=transport,
        )
        self.max_retries = max_retries
        self.page_limit = page_limit
        self._sleep = sleep
        self._min_remaining = min_remaining
        self.request_count = 0

    # ------------------------------------------------------------------ low level
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> OktaClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _request(
        self, method: str, url: str, params: dict[str, Any] | None = None, json: Any = None
    ) -> httpx.Response:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self._http.request(method, url, params=params, json=json)
            except httpx.TransportError as e:
                if attempt > self.max_retries:
                    raise
                delay = min(2 ** (attempt - 1), 30)
                log.warning("transport error %s for %s; retry %d in %ss", e, url, attempt, delay)
                self._sleep(delay)
                continue
            self.request_count += 1
            if resp.status_code == 429 or (resp.status_code >= 500 and attempt <= self.max_retries):
                if attempt > self.max_retries:
                    raise OktaAPIError(resp.status_code, str(resp.url), _safe_json(resp))
                delay = self._retry_delay(resp, attempt)
                log.warning("HTTP %d for %s; retry %d in %.1fs", resp.status_code, url, attempt, delay)
                self._sleep(delay)
                continue
            if resp.status_code >= 400:
                raise OktaAPIError(resp.status_code, str(resp.url), _safe_json(resp))
            self._preemptive_backoff(resp)
            return resp

    def _retry_delay(self, resp: httpx.Response, attempt: int) -> float:
        reset = resp.headers.get("X-Rate-Limit-Reset")
        date = resp.headers.get("Date")
        if reset:
            try:
                reset_epoch = float(reset)
                now = _parse_http_date(date) if date else time.time()
                return max(1.0, min(reset_epoch - now + 1.0, 120.0))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    def _preemptive_backoff(self, resp: httpx.Response) -> None:
        remaining = resp.headers.get("X-Rate-Limit-Remaining")
        reset = resp.headers.get("X-Rate-Limit-Reset")
        if remaining is None or reset is None:
            return
        try:
            if int(remaining) <= self._min_remaining:
                now = _parse_http_date(resp.headers.get("Date")) if resp.headers.get("Date") else time.time()
                delay = max(0.0, min(float(reset) - now + 1.0, 120.0))
                if delay:
                    log.info("rate limit nearly exhausted; sleeping %.1fs", delay)
                    self._sleep(delay)
        except ValueError:
            return

    # ------------------------------------------------------------------ public API
    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET a single resource (or a non-paginated list) and return the parsed JSON."""
        return self._request("GET", path, params=params).json()

    def post(self, path: str, json: Any) -> Any:
        """POST (used only for the policy simulation endpoint)."""
        return self._request("POST", path, json=json).json()

    def paginate(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Iterate over all items of a paginated collection, following ``Link rel=next``."""
        params = dict(params or {})
        params.setdefault("limit", self.page_limit)
        url: str | None = path
        first = True
        while url:
            resp = self._request("GET", url, params=params if first else None)
            first = False
            page = resp.json()
            if not isinstance(page, list):
                raise OktaAPIError(resp.status_code, str(resp.url), {"errorSummary": "expected a JSON array"})
            yield from page
            url = parse_next_link(resp.headers.get("Link"))

    def list_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return list(self.paginate(path, params))


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


def _parse_http_date(value: str | None) -> float:
    if not value:
        return time.time()
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return time.time()
