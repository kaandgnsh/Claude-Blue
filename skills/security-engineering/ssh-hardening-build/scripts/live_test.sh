#!/usr/bin/env bash
# Live test of a generated sshd drop-in with a throwaway, unprivileged sshd on 127.0.0.1.
#
#   ./live_test.sh 00-cb-hardening.conf [port]
#
# Runs as a normal user (no root, no change to the system sshd): creates temporary host and
# user keys, starts sshd with the drop-in, then checks from a client that key login works for
# the current user and that password auth, weak ciphers/KEX/MACs and TCP forwarding are refused.
# The drop-in's AllowGroups must include the current user's primary group for the positive test.
set -euo pipefail
export LC_ALL=C

CONF=$(realpath "${1:?usage: live_test.sh dropin.conf [port]}")
PORT=${2:-22922}
SSHD=$(command -v sshd || true)
[[ -x "$SSHD" ]] || { echo "sshd not found" >&2; exit 2; }
WORK=$(mktemp -d)
trap 'kill "${PID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

ssh-keygen -q -t ed25519 -N '' -f "$WORK/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/userkey"
cp "$WORK/userkey.pub" "$WORK/authorized_keys"
# sshd keeps the FIRST value of most keywords: these test-only settings come before the include
# so the throwaway server always binds 127.0.0.1:$PORT and uses temporary keys.
cat >"$WORK/sshd_config" <<CFG
Port $PORT
ListenAddress 127.0.0.1
HostKey $WORK/hostkey
PidFile none
AuthorizedKeysFile $WORK/authorized_keys
StrictModes no
Include $CONF
CFG
"$SSHD" -t -f "$WORK/sshd_config"
"$SSHD" -D -e -f "$WORK/sshd_config" 2>"$WORK/sshd.log" &
PID=$!
sleep 1

opts=(-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=3 -o IdentitiesOnly=yes -p "$PORT")
fail=0
check() {  # name expect(ok|refused) command...
  local name=$1 expect=$2; shift 2
  local out rc=0
  out=$("$@" 2>&1) || rc=$?
  local got=refused; [[ $rc -eq 0 ]] && got=ok
  if [[ $got == "$expect" ]]; then printf 'ok   %-34s %s\n' "$name" "$got"
  else printf 'FAIL %-34s expected=%s got=%s\n     %s\n' "$name" "$expect" "$got" "${out##*$'\n'}"; fail=$((fail + 1)); fi
}
check "key login (allowed user)" ok ssh "${opts[@]}" -i "$WORK/userkey" 127.0.0.1 true
# BatchMode can never type a password, so a failed login proves nothing. Instead read the
# methods the server offers ("Authentications that can continue: ...").
methods=$(ssh "${opts[@]}" -o PubkeyAuthentication=no -v 127.0.0.1 true 2>&1 \
          | grep -m1 -o 'Authentications that can continue: .*' | cut -d' ' -f5- || true)
if [[ -n "$methods" && ! "$methods" =~ (password|keyboard-interactive) ]]; then
  printf 'ok   %-34s %s\n' "only key-based methods offered" "$methods"
else
  printf 'FAIL %-34s offered=%s\n' "only key-based methods offered" "${methods:-none}"; fail=$((fail + 1))
fi
check "cipher aes128-cbc" refused ssh "${opts[@]}" -i "$WORK/userkey" -c aes128-cbc 127.0.0.1 true
check "kex diffie-hellman-group14-sha1" refused ssh "${opts[@]}" -i "$WORK/userkey" \
  -o KexAlgorithms=diffie-hellman-group14-sha1 127.0.0.1 true
check "mac hmac-sha1" refused ssh "${opts[@]}" -i "$WORK/userkey" -o Ciphers=aes128-ctr -o MACs=hmac-sha1 127.0.0.1 true
if grep -qx 'AllowTcpForwarding no' "$CONF"; then
  # -R is checked by the server at request time (with -L the refusal happens only when a
  # connection is made through the tunnel), so it gives a reliable signal.
  check "remote port forwarding (-R)" refused timeout 8 ssh "${opts[@]}" -i "$WORK/userkey" -o ExitOnForwardFailure=yes \
    -R "127.0.0.1:$((PORT + 1)):127.0.0.1:$PORT" 127.0.0.1 true
fi
kex=$(ssh "${opts[@]}" -i "$WORK/userkey" -v 127.0.0.1 true 2>&1 | grep -m1 -o 'kex: algorithm: .*' || true)
echo "info negotiated ${kex:-unknown}"
echo "failures=$fail"
[[ $fail -eq 0 ]]
