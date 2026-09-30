"""ssrf-probe: an authorized SSRF testing toolkit.

Only use this against systems you own or are explicitly permitted to test.
"""

__version__ = "0.1.0"

from .payloads import Payload, all_payloads
from .engine import Engine, ProbeResult, PLACEHOLDER
from .listener import CallbackListener, Callback

__all__ = [
    "Payload",
    "all_payloads",
    "Engine",
    "ProbeResult",
    "PLACEHOLDER",
    "CallbackListener",
    "Callback",
    "__version__",
]
