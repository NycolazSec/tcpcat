#!/bin/bash
# Phase 4 Evasion Options Testing Script

set -e

cd "$(dirname "$0")/.."

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║     Phase 4 Evasion Options - Comprehensive Testing Suite           ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo

BINARY="./tcpcat"
TARGET="127.0.0.1"
PORTS="22,80,443"

if [ ! -f "$BINARY" ]; then
    echo "[!] Error: tcpcat binary not found. Building..."
    go build -o tcpcat ./cmd/tcpcat
fi

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Helper function to run test
run_test() {
    local test_name="$1"
    local cmd="$2"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo -n "[$TEST_COUNT] Testing: $test_name... "
    
    if eval "$cmd" > /tmp/tcpcat_test_output.txt 2>&1; then
        if grep -q "Evasion Mode:" /tmp/tcpcat_test_output.txt || grep -q "Host discovery skipped" /tmp/tcpcat_test_output.txt; then
            echo "✅ PASS"
            PASS_COUNT=$((PASS_COUNT + 1))
            return 0
        else
            echo "❌ FAIL (No output detected)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            return 1
        fi
    else
        echo "❌ FAIL (Exit code: $?)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 1: Basic Evasion Modes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Evasion OFF" \
    "$BINARY -Pn -sT -p $PORTS --evasion off $TARGET"

run_test "Evasion LIGHT" \
    "$BINARY -Pn -sT -p $PORTS --evasion light $TARGET"

run_test "Evasion MODERATE" \
    "$BINARY -Pn -sT -p $PORTS --evasion moderate $TARGET"

run_test "Evasion AGGRESSIVE" \
    "$BINARY -Pn -sT -p $PORTS --evasion aggressive $TARGET"

run_test "Evasion STEALTHY" \
    "$BINARY -Pn -sT -p $PORTS --evasion stealthy $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 2: Jitter Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Jitter 0.0 (No jitter)" \
    "$BINARY -Pn -sT -p $PORTS --jitter 0.0 $TARGET"

run_test "Jitter 0.3 (Light)" \
    "$BINARY -Pn -sT -p $PORTS --jitter 0.3 $TARGET"

run_test "Jitter 0.5 (Moderate)" \
    "$BINARY -Pn -sT -p $PORTS --jitter 0.5 $TARGET"

run_test "Jitter 0.8 (Aggressive)" \
    "$BINARY -Pn -sT -p $PORTS --jitter 0.8 $TARGET"

run_test "Jitter 1.0 (Maximum)" \
    "$BINARY -Pn -sT -p $PORTS --jitter 1.0 $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 3: Fragmentation Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Fragment OFF" \
    "$BINARY -Pn -sT -p $PORTS $TARGET"

run_test "Fragment ON" \
    "$BINARY -Pn -sT -p $PORTS --frag $TARGET"

run_test "Fragment + Jitter" \
    "$BINARY -Pn -sT -p $PORTS --frag --jitter 0.4 $TARGET"

run_test "Fragment + Evasion MODERATE" \
    "$BINARY -Pn -sT -p $PORTS --frag --evasion moderate $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 4: TTL Mode Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "TTL Mode FIXED" \
    "$BINARY -Pn -sT -p $PORTS --ttl-mode fixed $TARGET"

run_test "TTL Mode RANDOM" \
    "$BINARY -Pn -sT -p $PORTS --ttl-mode random $TARGET"

run_test "TTL Mode PROBE" \
    "$BINARY -Pn -sT -p $PORTS --ttl-mode probe $TARGET"

run_test "TTL Mode RANDOM + Probe TTL 32" \
    "$BINARY -Pn -sT -p $PORTS --ttl-mode random --probe-ttl 32 $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 5: Window Size Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Window Size AUTO" \
    "$BINARY -Pn -sT -p $PORTS --window-size 0 $TARGET"

run_test "Window Size 512" \
    "$BINARY -Pn -sT -p $PORTS --window-size 512 $TARGET"

run_test "Window Size 2048" \
    "$BINARY -Pn -sT -p $PORTS --window-size 2048 $TARGET"

run_test "Window Size 65535 (Maximum)" \
    "$BINARY -Pn -sT -p $PORTS --window-size 65535 $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 6: Source Port Mode Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Source Port FIXED" \
    "$BINARY -Pn -sT -p $PORTS --source-port-mode fixed $TARGET"

run_test "Source Port RANDOM" \
    "$BINARY -Pn -sT -p $PORTS --source-port-mode random $TARGET"

run_test "Source Port + Port 12345" \
    "$BINARY -Pn -sT -p $PORTS -g 12345 --source-port-mode fixed $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST GROUP 7: Combined Evasion Options"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

run_test "Evasion LIGHT + Jitter" \
    "$BINARY -Pn -sT -p $PORTS --evasion light --jitter 0.3 $TARGET"

run_test "Evasion MODERATE + Fragment + Jitter" \
    "$BINARY -Pn -sT -p $PORTS --evasion moderate --frag --jitter 0.5 $TARGET"

run_test "Evasion AGGRESSIVE + All Options" \
    "$BINARY -Pn -sT -p $PORTS --evasion aggressive --jitter 0.7 --frag --ttl-mode random --window-size 1024 $TARGET"

run_test "Evasion STEALTHY + Full Config" \
    "$BINARY -Pn -sT -p $PORTS --evasion stealthy --jitter 0.9 --frag --decoy 192.168.1.1,10.0.0.1 --ttl-mode random $TARGET"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Total Tests:  $TEST_COUNT"
echo "Passed:       $PASS_COUNT ✅"
echo "Failed:       $FAIL_COUNT ❌"
echo
if [ $FAIL_COUNT -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed. Check /tmp/tcpcat_test_output.txt for details."
    exit 1
fi
