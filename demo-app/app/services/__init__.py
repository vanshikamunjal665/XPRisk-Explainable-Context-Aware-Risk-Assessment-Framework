"""Business logic for the XPRisk demo application.

Pure functions only. Nothing in this package imports Flask, touches the network
or reads configuration, which keeps the logic directly unit testable and gives
static analysis a clean module to analyse.

Phase 3 adds deliberately flawed logic in a sibling module. Keeping it apart
means the clean baseline and the vulnerable scenario never contaminate each
other, and the difference between them is obvious during a demonstration.
"""

from .greeting import calculate, describe_operation, greeting_for

__all__ = ["calculate", "describe_operation", "greeting_for"]