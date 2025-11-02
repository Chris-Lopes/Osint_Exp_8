import httpx, backoff
from .env import load, getenv

_cfg = load()
_timeout = _cfg["http"].get("timeout_seconds", 30)
_user_agent = _cfg["http"].get("user_agent", "Threat-Aggregation-Lab/1.0")

def _giveup(exc):
    """Determine if we should give up retrying based on HTTP status."""
    return isinstance(exc, httpx.HTTPStatusError) and 400 <= exc.response.status_code < 500

@backoff.on_exception(backoff.expo, (httpx.RequestError, httpx.HTTPStatusError), 
                     max_tries=3, giveup=_giveup)
def get(url: str, params: dict | None = None, headers: dict | None = None):
    """HTTP GET with retries and backoff."""
    h = {"User-Agent": _user_agent}
    if headers:
        h.update(headers)
    
    with httpx.Client(timeout=_timeout) as client:
        resp = client.get(url, params=params, headers=h)
        resp.raise_for_status()
        return resp

def auth_header_from_env(env_key: str, header_name: str = "Authorization", prefix: str = "Bearer "):
    """Create auth header from environment variable."""
    token = getenv(env_key, "")
    return {header_name: f"{prefix}{token}"} if token else {}