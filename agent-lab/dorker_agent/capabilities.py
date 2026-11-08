"""Default-deny capability policy for future agent tools."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    allowed: frozenset[str] = frozenset()

    def permits(self, capability: str) -> bool:
        if not capability or not capability.strip():
            return False
        return capability in self.allowed

    def require(self, capability: str) -> None:
        if not self.permits(capability):
            raise PermissionError(f"Capability denied: {capability}")


DEFAULT_POLICY = CapabilityPolicy()
