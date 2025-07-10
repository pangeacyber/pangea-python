#!/usr/bin/env bash

set -e

cd -- "$(dirname -- "$0")/.."

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/specs/ai-guard.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_ai_guard.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/specs/audit.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_audit.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/specs/authn.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_authn.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/specs/authz.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_authz.py"

pnpm dlx start-server-and-test --expect 404 \
  "pnpm dlx @stoplight/prism-cli mock -d --json-schema-faker-fillProperties=false tests/testdata/specs/share.openapi.json" \
  4010 \
  "poetry run pytest tests/integration2/test_share.py"
