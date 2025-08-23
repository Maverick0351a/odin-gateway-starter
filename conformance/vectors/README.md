Test Vectors (Draft)

This directory contains canonical JSON fixtures and expected verification behaviors
used by the automated conformance harness to issue an "ODIN Verified" badge.

Categories:
* envelope_basic: Minimal envelope signing + CID verification
* export_chain: Multi‑receipt chain + export bundle signature & linkage
* transparency_inclusion: Export inclusion proof verification against Merkle log

Each vector JSON:
{
  "name": "human readable",
  "input": { ... },   # Input payload or envelope fields
  "expected": { ... } # Expected normalized target, cids, booleans
}

Add new files with a short unique slug. The harness ignores files starting with '_' or non .json extensions.

Status: Draft – will evolve as spec hardens. Additive only.
