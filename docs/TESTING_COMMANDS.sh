#!/bin/bash
# Phase 4 Evasion Testing Commands
# Test suite for advanced IDS/IPS evasion techniques

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Phase 4: Advanced Evasion Techniques - Testing Suite        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

# 1. UNIT TESTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  UNIT TESTS - Run all evasion tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -v ./internal/evasion"
echo "Description: Run all unit tests with verbose output"
echo

# 2. RACE DETECTION
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  RACE DETECTION - Check for concurrent access issues"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -race -v ./internal/evasion"
echo "Description: Run tests with race condition detector"
echo

# 3. BENCHMARK TESTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  BENCHMARKS - Performance analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -bench=. -benchmem ./internal/evasion"
echo "Description: Run benchmarks with memory allocation stats"
echo

# 4. COVERAGE REPORT
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  CODE COVERAGE - Test coverage analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -cover ./internal/evasion"
echo "Description: Show test coverage percentage"
echo
echo "Command: go test -coverprofile=coverage.out ./internal/evasion && go tool cover -html=coverage.out"
echo "Description: Generate HTML coverage report"
echo

# 5. BUILD TESTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5️⃣  BUILD TESTS - Verify compilation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go build ./internal/evasion"
echo "Description: Build evasion package"
echo
echo "Command: go build ./internal/scan"
echo "Description: Build scan package with evasion integration"
echo
echo "Command: go build ./..."
echo "Description: Build entire project"
echo

# 6. LINTING
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6️⃣  LINTING - Code quality checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go fmt ./internal/evasion"
echo "Description: Format code"
echo
echo "Command: go vet ./internal/evasion"
echo "Description: Run static analyzer"
echo

# 7. INDIVIDUAL COMPONENT TESTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7️⃣  INDIVIDUAL TESTS - Test specific components"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -run TestAdaptiveJitterEngine -v ./internal/evasion"
echo "Description: Test jitter timing engine"
echo
echo "Command: go test -run TestFragmentationEngine -v ./internal/evasion"
echo "Description: Test fragmentation engine"
echo
echo "Command: go test -run TestDecoySwarmEngine -v ./internal/evasion"
echo "Description: Test decoy swarm orchestration"
echo
echo "Command: go test -run TestProtocolEvasion -v ./internal/evasion"
echo "Description: Test protocol-level evasion"
echo
echo "Command: go test -run TestMLAdaptiveEngine -v ./internal/evasion"
echo "Description: Test ML adaptation engine"
echo
echo "Command: go test -run TestBehavioralMimicryEngine -v ./internal/evasion"
echo "Description: Test behavioral mimicry"
echo
echo "Command: go test -run TestEvasionOrchestrator -v ./internal/evasion"
echo "Description: Test orchestrator"
echo

# 8. BENCHMARK INDIVIDUAL COMPONENTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8️⃣  COMPONENT BENCHMARKS - Performance profiling"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -bench=BenchmarkAdaptiveJitter -benchmem ./internal/evasion"
echo "Description: Benchmark jitter generation (1000 packets)"
echo
echo "Command: go test -bench=BenchmarkFragmentation -benchmem ./internal/evasion"
echo "Description: Benchmark packet fragmentation"
echo
echo "Command: go test -bench=BenchmarkMLPrediction -benchmem ./internal/evasion"
echo "Description: Benchmark ML detection prediction"
echo

# 9. INTEGRATION TESTS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "9️⃣  INTEGRATION TESTS - Scanner integration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -v ./internal/scan"
echo "Description: Test scanner with evasion integration"
echo

# 10. FULL TEST SUITE
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔟 FULL TEST SUITE - Complete validation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Command: go test -v -race ./..."
echo "Description: Run all tests with race detection"
echo

echo
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   QUICK START COMMANDS                        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo
echo "📌 Run ALL tests with race detection:"
echo "   go test -v -race ./internal/evasion"
echo
echo "📌 Run benchmarks:"
echo "   go test -bench=. -benchmem ./internal/evasion"
echo
echo "📌 Check coverage:"
echo "   go test -cover ./internal/evasion"
echo
echo "📌 Full validation (recommended):"
echo "   go test -v -race ./... && go build ./..."
echo
echo "📌 Format and lint:"
echo "   go fmt ./internal/evasion && go vet ./internal/evasion"
echo
