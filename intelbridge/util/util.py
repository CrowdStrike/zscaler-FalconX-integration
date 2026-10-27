"""
util.py
Helper methods for intel bridge module
"""
import configparser
import datetime
import email.utils
import json
import logging
import math
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

# Placeholder written in place of any sensitive value.
REDACTED = "[REDACTED]"
# Header names (lower-case) whose values must never be logged.
SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
})
# JSON / form / query field names (lower-case) whose values must never be logged.
SENSITIVE_FIELDS = frozenset({
    "password", "apikey", "api_key", "token", "access_token", "refresh_token",
    "secret", "client_secret", "jsessionid",
})
# Delay used when a 429 response has no usable Retry-After header.
DEFAULT_RETRY_AFTER_SECONDS = 60
# Optional config.ini section holding timeout and retry settings.
HTTP_SECTION = "HTTP"

_T = TypeVar("_T")


@dataclass(frozen=True)
class HttpSettings:
    """Timeout and retry settings from the optional [HTTP] config section.

    Attributes:
        connect_timeout: Seconds allowed to establish a connection.
        read_timeout: Seconds allowed to wait for a response.
        max_retries: Retries after a failed attempt; 0 disables retrying.
        retry_backoff: Delay before the first retry, doubled on each retry.
    """

    connect_timeout: float = 10.0
    read_timeout: float = 120.0
    max_retries: int = 5
    retry_backoff: float = 30.0

    @property
    def timeout(self) -> tuple[float, float]:
        """The ``(connect, read)`` timeout tuple accepted by requests and falconpy."""
        return (self.connect_timeout, self.read_timeout)


def _setting(section: Mapping[str, str], key: str, default: _T,
             parse: Callable[[str], _T], valid: Callable[[_T], bool], requirement: str) -> _T:
    """Read and validate one value from the [HTTP] section.

    Args:
        section: The config section (missing keys yield ``default``).
        key: Option name.
        default: Value used when the option is absent.
        parse: Converts the raw string, raising ValueError if it cannot.
        valid: Returns True when the parsed value is acceptable.
        requirement: Human-readable description used in the error message.

    Returns:
        The parsed value, or ``default`` when the option is absent.

    Raises:
        ValueError: If the option is present but invalid.
    """
    raw = section.get(key)
    if raw is None:
        return default
    try:
        value = parse(raw.strip())
    except ValueError:
        value = None
    if value is None or not valid(value):
        raise ValueError(f"config.ini [{HTTP_SECTION}] {key} must be {requirement}; got {raw!r}")
    return value


def load_http_settings(config: configparser.ConfigParser) -> HttpSettings:
    """Build HttpSettings from config.ini, using defaults for anything unset.

    The [HTTP] section is optional so existing config files keep working.

    Args:
        config: The parsed config.ini.

    Returns:
        Validated timeout and retry settings.

    Raises:
        ValueError: If any [HTTP] value is present but invalid.
    """
    defaults = HttpSettings()
    if not config.has_section(HTTP_SECTION):
        return defaults
    section = config[HTTP_SECTION]

    def positive(value: float) -> bool:
        return math.isfinite(value) and value > 0

    def non_negative(value: float) -> bool:
        return math.isfinite(value) and value >= 0

    return HttpSettings(
        connect_timeout=_setting(section, "connect_timeout", defaults.connect_timeout,
                                 float, positive, "a number greater than 0"),
        read_timeout=_setting(section, "read_timeout", defaults.read_timeout,
                              float, positive, "a number greater than 0"),
        max_retries=_setting(section, "max_retries", defaults.max_retries,
                             int, lambda value: value >= 0, "a whole number of 0 or more"),
        retry_backoff=_setting(section, "retry_backoff", defaults.retry_backoff,
                               float, non_negative, "a number of 0 or more"),
    )


def wait_before_retry(failures: int, settings: HttpSettings, error: Exception) -> None:
    """Back off before the next attempt, or re-raise once retries are used up.

    The delay doubles with each consecutive failure: retry_backoff,
    2 x retry_backoff, 4 x retry_backoff, and so on.

    Args:
        failures: Consecutive failed attempts so far (1 for the first failure).
        settings: Retry limits and backoff.
        error: The exception from the latest attempt.

    Raises:
        Exception: ``error`` itself, once ``failures`` exceeds max_retries.
    """
    if failures > settings.max_retries:
        logging.error(f"Giving up after {settings.max_retries} retries: {error}")
        raise error
    delay = settings.retry_backoff * 2 ** (failures - 1)
    logging.info(f"Retry {failures}/{settings.max_retries} in {delay:g} seconds.")
    time.sleep(delay)




def start_log():
    """Utility method for configuring logger
    returns: configured logging object
    """
    date_time = time.strftime("%Y-%m-%d-%H_%M_%S", time.gmtime())
    file = f"logs/{date_time}_intel_bridge_log.log"
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p',
        handlers=[
            logging.FileHandler(file),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log utility started. Writing to ./{file}")
    return logging

def convert(seconds):
    """Utility method for runtime formatting
    seconds - integer value of seconds
    returns: formatted time string
    """
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)

def listSplit(srcList, subLists=1):
    length = len(srcList)
    return [ srcList[i*length // subLists: (i+1)*length // subLists] 
             for i in range(subLists) ]

def buffer(msg, progress, len):
    """Utility method for updating progress bar
    msg - message to print
    progress - current progress 0-4
    len - value being progressed to
    returns: new progress 
    """
    bars = ["\\", "|", "/", "-"]
    if progress >= 4:
        progress = 0
    i = bars[progress]
    dots = "." * progress
    print(f"{i*12} {msg} qty: {len}{dots}{' '*20}", end='\r')
    progress = progress + 1
    return progress

def increment(p, len):
    """Utility method used with buffer() to increment progress by 1
    p - progress object
    len - value being progressed to
    returns: updated progress object
    """
    p[1] = p[1] + 1
    p[0] = buffer(f"{p[3]} {p[1]}/{p[2]}", p[0], len)
    return p

def next_hour():
       return time.strftime("%I:%M:%p",time.localtime(time.time()+43200))

def _redact_fields(value: Any) -> Any:
    """Recursively replace the values of sensitive keys in parsed JSON.

    Args:
        value: A JSON-decoded value (dict, list or scalar).

    Returns:
        A copy of ``value`` with sensitive keys' values replaced by REDACTED.
    """
    if isinstance(value, dict):
        return {key: REDACTED if str(key).lower() in SENSITIVE_FIELDS else _redact_fields(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_fields(item) for item in value]
    return value


def _redact_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Redact sensitive values in decoded query-string or form pairs.

    Args:
        pairs: ``(name, value)`` pairs, as returned by ``parse_qsl``.

    Returns:
        The pairs with sensitive values replaced by REDACTED.
    """
    return [(name, REDACTED if name.lower() in SENSITIVE_FIELDS else value)
            for name, value in pairs]


def _redact_headers(headers: Any) -> list[str]:
    """Render headers as ``Name: value`` lines with sensitive values redacted.

    Args:
        headers: A mapping of header names to values.

    Returns:
        One formatted line per header.
    """
    return [f"{name}: {REDACTED if name.lower() in SENSITIVE_HEADERS else value}"
            for name, value in headers.items()]


def _redact_url(url: str) -> str:
    """Remove embedded credentials and sensitive query values from a URL.

    Args:
        url: Absolute request URL.

    Returns:
        The URL, unchanged unless it carried userinfo or sensitive parameters.
    """
    parts = urlsplit(url)
    if parts.username or parts.password:
        host = parts.hostname or ""
        parts = parts._replace(netloc=f"{host}:{parts.port}" if parts.port else host)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if any(name.lower() in SENSITIVE_FIELDS for name, _ in pairs):
        parts = parts._replace(query=urlencode(_redact_pairs(pairs), safe="[]"))
    return urlunsplit(parts)


def _describe_body(body: Any, content_type: str, opaque: Optional[str]) -> str:
    """Render an HTTP body for logging with sensitive fields redacted.

    JSON and form-encoded bodies are parsed and redacted. Any other body is
    either replaced by ``opaque`` (used for request bodies, which may carry
    secrets we cannot locate) or logged as text (used for response bodies,
    whose error messages are needed for debugging).

    Args:
        body: Raw body as bytes or str (anything else is treated as opaque).
        content_type: The Content-Type header value, or an empty string.
        opaque: Placeholder for unparseable bodies, with an optional
            ``{size}`` field; ``None`` to log such bodies verbatim.

    Returns:
        The loggable body, or an empty string when there is no body.
    """
    if not body:
        return ""
    if not isinstance(body, (bytes, str)):
        return opaque.format(size="unknown") if opaque else "[streamed body omitted]"
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        return json.dumps(_redact_fields(json.loads(text)))
    except ValueError:
        pass
    if "application/x-www-form-urlencoded" in content_type.lower():
        return urlencode(_redact_pairs(parse_qsl(text, keep_blank_values=True)), safe="[]")
    return opaque.format(size=len(text)) if opaque else text


def format_http_exchange(resp: requests.Response) -> str:
    """Describe a request/response pair for logs without secrets.

    Request lines are prefixed with ``<`` and response lines with ``>``,
    matching the layout of the requests-toolbelt dump this replaces.

    Args:
        resp: The response whose exchange should be described.

    Returns:
        A multi-line, redacted description of the exchange.
    """
    lines = []
    request = resp.request
    if request is not None:
        lines.append(f"< {request.method} {_redact_url(request.url or '')}")
        lines += [f"< {line}" for line in _redact_headers(request.headers)]
        request_body = _describe_body(request.body, request.headers.get("Content-Type", ""),
                                      opaque="[{size} byte non-JSON request body omitted]")
        if request_body:
            lines += ["<", f"< {request_body}"]
        lines.append("")
    lines.append(f"> HTTP {resp.status_code} {resp.reason or ''}".rstrip())
    lines += [f"> {line}" for line in _redact_headers(resp.headers)]
    response_body = _describe_body(resp.content, resp.headers.get("Content-Type", ""), opaque=None)
    if response_body:
        lines += [">", f"> {response_body}"]
    return "\n".join(lines)


def log_http_error(resp: requests.Response) -> None:
    """Log a failed HTTP exchange with credentials and tokens redacted.

    Args:
        resp: The failed response to describe.
    """
    logging.info("HTTP related failure:\n" + format_http_exchange(resp))


def retry_after_seconds(resp: requests.Response,
                        default: int = DEFAULT_RETRY_AFTER_SECONDS) -> int:
    """Return how long to wait before retrying, from the Retry-After header.

    Supports both forms allowed by RFC 9110: delay-seconds (``"120"``) and an
    HTTP-date. Uses only the public requests header API.

    Args:
        resp: A response (normally HTTP 429) that may carry Retry-After.
        default: Seconds to wait when the header is missing or malformed.

    Returns:
        A non-negative number of seconds.
    """
    value = resp.headers.get("Retry-After")
    if value is None:
        logging.info(f"No Retry-After header on HTTP {resp.status_code}; waiting {default}s.")
        return default
    value = value.strip()
    if value.isascii() and value.isdigit():
        return int(value)
    try:
        retry_at = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        logging.info(f"Unparseable Retry-After header {value!r}; waiting {default}s.")
        return default
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=datetime.timezone.utc)
    delay = (retry_at - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    return max(0, math.ceil(delay))

def write_data(entry, deleted):
    """Writes the next_page URL to disk so etl_loop can pick up where it left off
    entry - line to write to file
    deleted - boolean for deleted or new indicators
    returns: N/A
    """    
    new_indicators_data = f"logs/data_log/data_new"
    deleted_indicators_data = f"logs/data_log/data_deleted"
    data_file = new_indicators_data if not deleted else deleted_indicators_data
    data_file = data_file + "_" + time.strftime("%Y-%m-%d-%H_%M_%S", time.gmtime()) +".log"
    f = open(data_file, 'w')
    f.write(f"{entry}")
    f.close()
    return    

def write_rejected(message, entry):
    """writes rejected URLs to a log file
    """    
    rejected_indicators_data = f"logs/rejected_log/data_rejected"
    data_file = rejected_indicators_data
    data_file = data_file + "_" + time.strftime("%Y-%m-%d", time.gmtime()) +".log"
    f = open(data_file, 'w')
    f.write(f"{time.strftime('%Y-%m-%d', time.gmtime())}: {message}: {entry}")
    f.close()
    return    