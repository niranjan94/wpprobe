# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WPProbe is a Go CLI tool for WordPress plugin detection via REST API enumeration with CVE mapping. It detects 5000+ plugins using three scan modes (stealthy, bruteforce, hybrid) and correlates findings against Wordfence/WPScan vulnerability databases.

## Build & Development Commands

```sh
# Build
go build -o wpprobe ./main.go
go build -trimpath -ldflags="-X github.com/Chocapikk/wpprobe/internal/version.Version=dev" ./...

# Test
go test ./... -v -coverprofile=coverage.out -covermode=atomic

# Benchmarks (scanner, vulnerability, file packages)
go test -bench=. -benchmem ./internal/scanner/... ./internal/vulnerability/... ./internal/file/... -run=^$

# Run a single test
go test -v -run TestFunctionName ./internal/scanner/...

# Lint
golangci-lint run --timeout=5m
```

## Architecture

**Entry point:** `main.go` -> `cmd.Execute()` (Cobra CLI)

**Core packages in `internal/`:**
- `scanner/` - Plugin detection engine. Three modes: stealthy (REST API endpoint matching), bruteforce (directory checks), hybrid (both). Key files: `orchestration.go` (multi-target coordination), `modes.go` (mode selection), `detection.go` (endpoint matching with confidence scoring), `bruteforce.go`, `vulnerabilities.go` (CVE correlation with version range matching)
- `http/` - HTTP client wrapper with token-bucket rate limiting (`ratelimit.go`), proxy support, random User-Agent rotation, configurable redirects
- `vulnerability/` - Global vulnerability cache loaded once and shared across scanners. Version range matching (from/to with inclusive flags)
- `wordfence/` - Wordfence REST API integration (free, default source)
- `wpscan/` - WPScan API integration (requires `WPSCAN_API_TOKEN` env var, Enterprise plan)
- `file/` - Output formatting via `WriterInterface`: CSV, JSON, and `MemoryWriter` (for programmatic API use)
- `logger/` - Styled terminal logging with lipgloss
- `progress/` - Progress bar wrapper (schollz/progressbar)
- `version/` - Self-update and version checking
- `severity/` - Severity normalization across data sources
- `search/` - Vulnerability querying by CVE, plugin, severity, auth type

**Public API:** `pkg/wpprobe.go` exposes `Scanner` struct with `Config` for programmatic use with context cancellation support.

**CLI commands in `cmd/`:** scan, update-db, search, list, update, uninstall

**Data flow:** Load targets -> Load vulnerability DB -> Per-target scan (detect plugins -> match vulnerabilities) -> Write results (CSV/JSON)

## Key Conventions

- Go 1.23+ with toolchain 1.24+
- Table-driven tests throughout
- Vulnerability databases cached in `~/.config/wpprobe/`
- Version injected via ldflags: `-X github.com/Chocapikk/wpprobe/internal/version.Version=...`
- GoReleaser for multi-platform distribution (`.goreleaser.yaml`)
