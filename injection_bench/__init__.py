"""Deterministic prompt-injection benchmark for tool-using AI agents.

Scores compromise from the sandbox's recorded state, never from the agent's
transcript. An agent that says "I refused" while calling the tool is caught.
"""

__version__ = "0.1.0"
