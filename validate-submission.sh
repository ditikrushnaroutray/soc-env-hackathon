#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# validate-submission.sh — Pre-submission validation for OpenEnv
#
# Runs inference.py and checks structured output format.
# Usage: ./validate-submission.sh [ENV_URL]
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

ENV_URL="${1:-http://localhost:7860}"
PASS=0
FAIL=0
TOTAL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check() {
    local desc="$1"
    local result="$2"
    TOTAL=$((TOTAL + 1))
    if [ "$result" = "true" ]; then
        echo -e "  ${GREEN}✓ PASS${NC}: $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC}: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SOC Analyst Environment — Submission Validator"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── 1. Check server health ────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking server health...${NC}"
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${ENV_URL}/health" 2>/dev/null || echo "000")
check "Server responds on /health" "$([ "$HEALTH" = "200" ] && echo true || echo false)"

# ── 2. Check openenv.yaml exists ─────────────────────────────────
echo -e "${YELLOW}[2/5] Checking openenv.yaml...${NC}"
check "openenv.yaml exists" "$([ -f openenv.yaml ] && echo true || echo false)"

if [ -f openenv.yaml ]; then
    check "openenv.yaml contains task_easy" "$(grep -q 'task_easy' openenv.yaml && echo true || echo false)"
    check "openenv.yaml contains task_medium" "$(grep -q 'task_medium' openenv.yaml && echo true || echo false)"
    check "openenv.yaml contains task_hard" "$(grep -q 'task_hard' openenv.yaml && echo true || echo false)"
    check "openenv.yaml app points to server" "$(grep -q 'soc_analyst_env.server.app:app' openenv.yaml && echo true || echo false)"
fi

# ── 3. Check /reset endpoint ─────────────────────────────────────
echo -e "${YELLOW}[3/5] Checking /reset endpoint...${NC}"
RESET_RESP=$(curl -s -X POST "${ENV_URL}/reset" \
    -H "Content-Type: application/json" \
    -d '{"task_id": "task_easy"}' 2>/dev/null || echo '{}')

check "/reset returns session_id" "$(echo "$RESET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if 'session_id' in d else 'false')" 2>/dev/null || echo false)"
check "/reset returns observation" "$(echo "$RESET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if 'observation' in d else 'false')" 2>/dev/null || echo false)"

# ── 4. Run inference.py and validate output ───────────────────────
echo -e "${YELLOW}[4/5] Running inference.py (heuristic mode)...${NC}"

# Run with no API keys to trigger heuristic mode
OUTPUT=$(ENV_URL="${ENV_URL}" MODEL_NAME="heuristic" python3 inference.py 2>&1 || true)
EXIT_CODE=$?

check "inference.py exits with code 0" "$([ "$EXIT_CODE" = "0" ] && echo true || echo false)"

# Check [START] lines
for TASK in task_easy task_medium task_hard; do
    check "[START] present for $TASK" "$(echo "$OUTPUT" | grep -q "\[START\] task=${TASK}" && echo true || echo false)"
    check "[END] present for $TASK" "$(echo "$OUTPUT" | grep -q "\[END\] task=${TASK}" && echo true || echo false)"
done

# Check [END] format
check "[END] contains success= field" "$(echo "$OUTPUT" | grep '\[END\]' | head -1 | grep -q 'success=' && echo true || echo false)"
check "[END] contains steps= field" "$(echo "$OUTPUT" | grep '\[END\]' | head -1 | grep -q 'steps=' && echo true || echo false)"
check "[END] contains score= field" "$(echo "$OUTPUT" | grep '\[END\]' | head -1 | grep -q 'score=' && echo true || echo false)"
check "[END] contains rewards= field" "$(echo "$OUTPUT" | grep '\[END\]' | head -1 | grep -q 'rewards=' && echo true || echo false)"

# Check score bounds (extract all scores and verify they're in [0.001, 0.999])
echo -e "${YELLOW}[5/5] Checking score bounds...${NC}"
SCORES=$(echo "$OUTPUT" | grep '\[END\]' | grep -oP 'score=\K[0-9.]+' || echo "")
ALL_IN_BOUNDS=true
for SCORE in $SCORES; do
    IN_LOWER=$(python3 -c "print('true' if float('${SCORE}') >= 0.001 else 'false')" 2>/dev/null || echo false)
    IN_UPPER=$(python3 -c "print('true' if float('${SCORE}') <= 0.999 else 'false')" 2>/dev/null || echo false)
    if [ "$IN_LOWER" != "true" ] || [ "$IN_UPPER" != "true" ]; then
        ALL_IN_BOUNDS=false
    fi
done
check "All scores within (0.001, 0.999)" "$ALL_IN_BOUNDS"

# Check reward bounds
REWARDS=$(echo "$OUTPUT" | grep '\[STEP\]' | grep -oP 'reward=\K[0-9.]+' || echo "")
ALL_REWARDS_OK=true
for R in $REWARDS; do
    IN_L=$(python3 -c "print('true' if float('${R}') >= 0.001 else 'false')" 2>/dev/null || echo false)
    IN_U=$(python3 -c "print('true' if float('${R}') <= 0.999 else 'false')" 2>/dev/null || echo false)
    if [ "$IN_L" != "true" ] || [ "$IN_U" != "true" ]; then
        ALL_REWARDS_OK=false
    fi
done
check "All step rewards within (0.001, 0.999)" "$ALL_REWARDS_OK"

# Check boolean format (lowercase true/false)
check "Booleans are lowercase" "$(echo "$OUTPUT" | grep '\[END\]' | grep -qP 'success=(true|false)' && echo true || echo false)"

# ── Results Summary ───────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
echo "═══════════════════════════════════════════════════════════"

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}🎉 ALL CHECKS PASSED — Ready for submission!${NC}"
    echo ""
    exit 0
else
    echo -e "  ${RED}⚠  ${FAIL} check(s) failed. Fix before submitting.${NC}"
    echo ""
    exit 1
fi
