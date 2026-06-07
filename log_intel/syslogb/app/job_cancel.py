"""Shared exception for user-cancelled LLM analysis jobs."""


class JobCancelled(Exception):
    """Raised when the user cancels an analysis job."""
