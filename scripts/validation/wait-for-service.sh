#!/bin/bash
# A script to wait for a service to be healthy.
# Usage: ./wait-for-service.sh <url> [timeout_seconds]

URL=$1
TIMEOUT=${2:-60} # Default timeout is 60 seconds
START_TIME=$(date +%s)

echo "Waiting for service at $URL to be healthy (timeout: ${TIMEOUT}s)..."

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED_TIME -ge $TIMEOUT ]; then
        echo "Error: Timeout waiting for service at $URL"
        exit 1
    fi

    # Use curl to check the service. -s for silent, -o /dev/null to discard output,
    # -w "%{http_code}" to write only the status code to stdout.
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

    if [ "$STATUS_CODE" -eq 200 ]; then
        echo "Service at $URL is healthy (responded with 200)."
        exit 0
    fi

    echo "Service at $URL not ready yet (status code: $STATUS_CODE). Retrying in 5 seconds..."
    sleep 5
done
