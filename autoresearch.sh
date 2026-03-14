#!/bin/bash
set -euo pipefail

# Quick syntax check
go vet ./... 2>&1 | head -5

# Run only the SignAndEncrypt benchmark at the 100KB size (good balance of speed vs signal)
# Use -count=5 for stable results, -benchmem for allocation tracking
OUTPUT=$(go test -bench='BenchmarkSignAndEncrypt/100KB' -benchmem -count=5 -timeout=120s ./... 2>&1)

echo "$OUTPUT"

# Extract median ns/op from the benchmark output
# Go bench outputs lines like: BenchmarkSignAndEncrypt/100KB-8  123  4567890 ns/op
NS_PER_OP=$(echo "$OUTPUT" | grep 'BenchmarkSignAndEncrypt/100KB' | awk '{print $3}' | sort -n | head -3 | tail -1)
ALLOCS=$(echo "$OUTPUT" | grep 'BenchmarkSignAndEncrypt/100KB' | awk '{print $5}' | sort -n | head -3 | tail -1)
BYTES_PER_OP=$(echo "$OUTPUT" | grep 'BenchmarkSignAndEncrypt/100KB' | awk '{print $7}' | sort -n | head -3 | tail -1)

echo "METRIC ns_per_op=${NS_PER_OP}"
echo "METRIC allocs_per_op=${ALLOCS}"
echo "METRIC bytes_per_op=${BYTES_PER_OP}"
