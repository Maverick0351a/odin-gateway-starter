"""Top-level services package.

Adding this file ensures the 'services' namespace is explicitly recognized as a
regular package during CI test collection (some environments can fail to
resolve implicit namespace packages in edge cases)."""

__all__ = ["gateway", "relay", "dashboard"]
