package odin.policy

# Default deny
default allow = false

# Global host allowlist example
allow {
  input.host == "api.openai.com"
}

# Per-tenant override example
allow {
  input.tenant == "tenant-123"
  input.host == "postman-echo.com"
}

# Optional reasons array for richer receipt metadata
reasons := msgs {
  allow
  msgs := [sprintf("allow host %s", [input.host])]
}
