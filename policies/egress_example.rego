package odin.egress

default allow = false

# Allow only example.com and finance.api
allow {
  input.host == "example.com"
}

allow {
  input.host == "finance.api"
}
