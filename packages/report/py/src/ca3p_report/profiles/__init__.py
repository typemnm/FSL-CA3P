"""Vulnerability profiles: per-type writing hints for the LLM (no code enforcement)."""

from .registry import Profile, resolve_profile

__all__ = ["Profile", "resolve_profile"]
