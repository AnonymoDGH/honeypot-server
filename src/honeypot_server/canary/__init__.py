"""Canary tooling -- tokens and documents that trip alarms when touched.

The token generator (tokens) produces unique fake secrets and URLs; the
document generator (docs) plants them inside bait files that decoys serve.
"""

from __future__ import annotations

from .tokens import CanaryToken, CanaryTokenFactory, load_tokens, verify_jwt_shape

__all__ = ["CanaryToken", "CanaryTokenFactory", "load_tokens", "verify_jwt_shape"]
