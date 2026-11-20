#!/usr/bin/env bash
# ci.sh — one entry point for build+test, local or remote (remote.sh lane).
# Bootstraps a pinned Go toolchain when `go` is missing (remote boxes).
set -euo pipefail

GO_VERSION=1.22.10

if ! command -v go >/dev/null 2>&1; then
  case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH=amd64 ;;
  esac
  echo "installing go${GO_VERSION} (${ARCH}) to /tmp/gotc"
  mkdir -p /tmp/gotc
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/gotc/go.tgz
  mkdir -p /tmp/gotc/go-x
  tar -C /tmp/gotc/go-x --strip-components=1 -xzf /tmp/gotc/go.tgz
  export PATH="/tmp/gotc/go-x/bin:$PATH"
fi

mkdir -p remote-out
echo "go: $(go version)"
go mod tidy
go vet ./...
go build ./...
echo "--- test ---"
go test -race -timeout 120s ./... 2>&1 | tee remote-out/test.log
echo "--- bench (containment path budget) ---"
go test -run '^$' -bench BenchmarkGateContainment -benchtime 1s ./internal/gate/ 2>&1 | tee remote-out/bench.log
cp -f go.mod go.sum remote-out/ 2>/dev/null || true
echo "ci.sh: green"
