"""
Метаданные пакета Phantom и стабильные точки входа.
"""

from __future__ import annotations

__all__ = ["run", "__version__"]
__version__ = "1.0.0"


def run() -> None:
    from .__main__ import run as _run

    _run()

