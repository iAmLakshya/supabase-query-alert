#!/bin/bash
#
# Capture pgaudit logs from local Supabase PostgreSQL container.
#
# Usage:
#   ./scripts/capture_logs.sh              # Stream logs to stdout
#   OUTPUT_FILE=audit.log ./scripts/capture_logs.sh  # Write to file
#
# Requires: Docker running with Supabase local dev environment.

set -e

cleanup() {
    exit 0
}
trap cleanup SIGINT SIGTERM

CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'supabase.*db' | head -1)

if [ -z "$CONTAINER" ]; then
    echo "Error: Supabase database container not found." >&2
    echo "Ensure 'supabase start' has been run and Docker is running." >&2
    exit 1
fi

echo "Capturing pgaudit logs from container: $CONTAINER" >&2
echo "Press Ctrl+C to stop." >&2
echo "" >&2

if [ -n "$OUTPUT_FILE" ]; then
    docker logs -f "$CONTAINER" 2>&1 | grep --line-buffered "AUDIT" > "$OUTPUT_FILE"
else
    docker logs -f "$CONTAINER" 2>&1 | grep --line-buffered "AUDIT"
fi
