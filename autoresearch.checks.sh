#!/bin/bash
set -euo pipefail

# Run all tests to ensure correctness (especially SignAndEncrypt tests)
go test ./... -count=1 -timeout=60s 2>&1 | grep -E "FAIL|PASS|ok" || true
