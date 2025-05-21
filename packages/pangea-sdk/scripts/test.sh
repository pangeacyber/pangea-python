#!/usr/bin/env bash

set -e

cd -- "$(dirname -- "$0")/.."

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/ai-guard.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_ai_guard.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/prompt-guard.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_prompt_guard.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/share.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_share.py"
