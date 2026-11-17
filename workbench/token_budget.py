"""Conservative token budgeting for local-model review requests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenBudget:
    context_window: int
    input_limit: int
    output_reserve: int
    fixed_prompt_tokens: int
    diff_token_budget: int
    safety_ratio: float
    estimator: str = "utf8-byte-upper-bound"


def estimate_tokens_upper_bound(value: str) -> int:
    """Conservatively estimate tokens using UTF-8 bytes, not character count."""
    return len(value.encode("utf-8"))


def calculate_token_budget(
    *,
    system_prompt: str,
    user_prompt: str,
    context_window: int,
    output_reserve: int,
    safety_ratio: float = 0.90,
    framing_overhead: int = 128,
) -> TokenBudget:
    """Reserve output and safety headroom before allocating diff input."""
    if context_window <= 0:
        raise ValueError("context_window must be positive")
    if output_reserve <= 0 or output_reserve >= context_window:
        raise ValueError("output_reserve must be between zero and context_window")
    if not 0 < safety_ratio < 1:
        raise ValueError("safety_ratio must be between zero and one")
    if framing_overhead < 0:
        raise ValueError("framing_overhead cannot be negative")

    input_limit = min(
        int(context_window * safety_ratio),
        context_window - output_reserve,
    )
    fixed_prompt_tokens = (
        estimate_tokens_upper_bound(system_prompt)
        + estimate_tokens_upper_bound(user_prompt)
        + framing_overhead
    )
    diff_token_budget = input_limit - fixed_prompt_tokens
    if diff_token_budget <= 0:
        raise ValueError(
            "System and user prompts exceed the safe input budget; "
            "reduce prompt size or increase the configured context window"
        )

    return TokenBudget(
        context_window=context_window,
        input_limit=input_limit,
        output_reserve=output_reserve,
        fixed_prompt_tokens=fixed_prompt_tokens,
        diff_token_budget=diff_token_budget,
        safety_ratio=safety_ratio,
    )
