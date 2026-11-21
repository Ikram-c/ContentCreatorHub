"""Runtime verification contracts, bounded loops, and checked result types."""

from dataclasses import dataclass
from typing import Generic, Optional, Sequence, Tuple, TypeVar

from content_hub.constants import MAX_LOOP_ITERATIONS, ZERO_INT

T = TypeVar("T")


class ContractViolationError(RuntimeError):
    """Raised when a runtime precondition or postcondition check fails."""


@dataclass(frozen=True)
class OperationResult(Generic[T]):
    """Immutable outcome container requiring explicit caller inspection.

    Attributes:
        ok: True when the operation succeeded without errors.
        value: Resulting typed payload when ok is True, otherwise None.
        error_code: Machine-readable error identifier when ok is False.
        http_status: Associated HTTP status code for API gateway handling.
    """

    ok: bool
    value: Optional[T]
    error_code: str = ""
    http_status: int = ZERO_INT


def verify_condition(condition: bool, message: str) -> bool:
    """Validates a runtime invariant and raises ContractViolationError if False.

    Args:
        condition: Boolean expression expected to evaluate to True.
        message: Diagnostic message describing the violated contract.

    Returns:
        True when condition evaluates to True.

    Raises:
        ContractViolationError: If condition is not a True boolean.
    """
    if not isinstance(condition, bool) or not condition:
        raise ContractViolationError(f"Contract check failed: {message}")
    return True


def bounded_range(limit: int, ceiling: int = MAX_LOOP_ITERATIONS) -> range:
    """Constructs an iteration range strictly capped at ceiling.

    Args:
        limit: Requested upper bound for iteration.
        ceiling: Hard maximum iteration ceiling permitted.

    Returns:
        Standard range object starting at zero and capped at ceiling.
    """
    verify_condition(limit >= ZERO_INT, "Loop limit must be non-negative")
    verify_condition(ceiling > ZERO_INT, "Loop ceiling must be positive")
    effective_limit: int = limit if limit <= ceiling else ceiling
    result_range: range = range(ZERO_INT, effective_limit)
    verify_condition(
        len(result_range) <= ceiling,
        "Constructed range exceeded ceiling",
    )
    return result_range


def verify_state_transition(
    current_state: str,
    target_state: str,
    allowed_edges: Sequence[Tuple[str, str]],
) -> OperationResult[str]:
    """Verifies that transitioning from current_state to target_state is valid.

    Args:
        current_state: Active state identifier string.
        target_state: Requested destination state identifier string.
        allowed_edges: Sequence of permitted (source, destination) pairs.

    Returns:
        OperationResult wrapping target_state when permitted.
    """
    edge_count: int = len(allowed_edges)
    verify_condition(edge_count > ZERO_INT, "Transition edges cannot be empty")
    for idx in bounded_range(edge_count):
        src_state, dst_state = allowed_edges[idx]
        if src_state == current_state and dst_state == target_state:
            return OperationResult(ok=True, value=target_state)
    return OperationResult(
        ok=False,
        value=None,
        error_code=f"ILLEGAL_TRANSITION_{current_state}_TO_{target_state}",
    )
