#!/usr/bin/env bash
# Verify the three things that must line up for the n8n -> syschange shim path.
# Exits non-zero and says exactly what broke, instead of failing silently the
# way SHIM_BIND=auto did.
set -uo pipefail

PORT="${SHIM_PORT:-9922}"
BRIDGE_IP="${SHIM_BIND:-172.19.0.1}"
NET="n8n-workflows_n8n-net"
ok=0

echo "1. shim service state"
if systemctl --user is-active --quiet sandbox-shim.service; then
  echo "   ✅ sandbox-shim.service active"
else
  echo "   ❌ sandbox-shim.service NOT active"; ok=1
fi

echo "2. shim listening where n8n can reach it"
if ss -tln 2>/dev/null | grep -q "$BRIDGE_IP:$PORT"; then
  echo "   ✅ bound to $BRIDGE_IP:$PORT"
else
  echo "   ❌ not bound to $BRIDGE_IP:$PORT (if it says 127.0.0.1, SHIM_BIND is wrong)"; ok=1
fi

echo "3. $BRIDGE_IP still belongs to the $NET bridge"
if ip -4 addr 2>/dev/null | grep -q "$BRIDGE_IP/"; then
  echo "   ✅ $BRIDGE_IP present on this host"
  if ip -4 addr 2>/dev/null | grep -qB3 "$BRIDGE_IP/" && \
     ip -4 addr 2>/dev/null | grep -B3 "$BRIDGE_IP/" | grep -qE "br-[a-f0-9]+"; then
    echo "   ✅ attached to a docker bridge"
  fi
else
  echo "   ⚠  $BRIDGE_IP gone — the n8n network was recreated."
  echo "      New gateway: $(docker network inspect "$NET" \
        --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)"
  echo "      Then update SHIM_BIND in sandbox-shim.service and re-add the ufw rule:"
  echo "        sudo ufw allow in on <new-br> to <new-gateway> port $PORT proto tcp"
  ok=1
fi

echo "4. ufw allows container -> shim"
if command -v ufw >/dev/null; then
  echo "   (checking needs root — run: sudo ufw status | grep $PORT)"
fi

echo "5. n8n container can actually reach the shim"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q n8n; then
  if docker exec n8n-workflows-n8n-1 node -e "
      const t=setTimeout(()=>process.exit(2),6000);
      fetch('http://$BRIDGE_IP:$PORT/health')
        .then(r=>r.json()).then(j=>{console.log('   ✅ from inside n8n:',JSON.stringify(j));process.exit(0)})
        .catch(()=>process.exit(1));
    " 2>/dev/null; then
    :
  else
    rc=$?
    case $rc in
      1) echo "   ❌ timeout/refused — check the ufw rule and that shim is bound to $BRIDGE_IP"; ok=1 ;;
      2) echo "   ❌ timed out from inside n8n"; ok=1 ;;
    esac
  fi
else
  echo "   ⏭  n8n is asleep (start it with: stackctl start n8n)"
fi

echo
[ $ok -eq 0 ] && echo "✅ shim path looks good" || echo "❌ something above is broken"
exit $ok
