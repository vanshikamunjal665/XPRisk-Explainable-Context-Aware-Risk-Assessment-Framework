"""Greeting and calculation logic.

Deliberately trivial, dependency-free functions. They exist so the demo
application has genuine business logic for SonarQube to analyse, and so the
API has something meaningful to expose.
"""

from __future__ import annotations

from typing import Final

DEFAULT_NAME: Final[str] = "World"
MAX_NAME_LENGTH: Final[int] = 64

SUPPORTED_OPERATIONS: Final[tuple[str, ...]] = ("add", "subtract", "multiply")


def greeting_for(name: str | None = None) -> str:
    """Build a greeting for a caller.

    Args:
        name: Caller name. ``None`` or blank falls back to
            :data:`DEFAULT_NAME`. The value is trimmed and length limited so
            the response cannot be used to inject arbitrary content.

    Returns:
        A human readable greeting.
    """
    if name is None:
        candidate = DEFAULT_NAME
    else:
        candidate = name.strip()

    if not candidate:
        candidate = DEFAULT_NAME

    candidate = candidate[:MAX_NAME_LENGTH]
    return f"Hello, {candidate}! Welcome to the XPRisk demo application."


def describe_operation(operation: str) -> str:
    """Return a readable label for a supported arithmetic operation.

    Args:
        operation: Operation identifier supplied by the caller.

    Returns:
        A readable label, or a ``not supported`` message when the identifier is
        unknown. Unknown input is handled rather than raised, because this
        backs a user-facing endpoint.
    """
    labels: dict[str, str] = {
        "add": "addition",
        "subtract": "subtraction",
        "multiply": "multiplication",
    }
    label = labels.get(operation.strip().lower())
    if label is None:
        supported = ", ".join(SUPPORTED_OPERATIONS)
        return f"Operation '{operation}' is not supported. Supported: {supported}."
    return f"Performing {label}."


def calculate(left: float, right: float, operation: str) -> float:
    """Apply an arithmetic operation to two numbers.

    Args:
        left: Left operand.
        right: Right operand.
        operation: One of :data:`SUPPORTED_OPERATIONS`.

    Returns:
        The result of the operation.

    Raises:
        ValueError: If the operation is not supported.
    """
    normalised = operation.strip().lower()
    if normalised == "add":
        return left + right
    if normalised == "subtract":
        return left - right
    if normalised == "multiply":
        return left * right

    supported = ", ".join(SUPPORTED_OPERATIONS)
    raise ValueError(f"Unsupported operation '{operation}'. Supported: {supported}.")