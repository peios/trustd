# Guest-side smoke test for trustd. Run with
#   dist/release/drive.py --no-disk --share <dir> --timeout 300 \
#     --cmdline-extra 'loglevel=7 ignore_loglevel' <dir>/smoke.sh
# and read <dir>/trustd-report.txt plus the trustd: lines on the console.
#
# No grep, sed or awk: the image ships peiosutils, a coreutils fork, and has
# none of them. Every assertion that needs to look inside the store asks
# `trust`, which is the authoritative answer anyway — the files are a
# rendering of what the socket serves, so checking the socket and checking
# that the files exist is the right division.
{
  echo "== service"; svctl status trustd | head -2
  echo "== status"; trust status

  echo "== the three artifacts exist where each consumer looks"
  for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
    if [ -f "$f" ]; then echo "ok   $f ($(wc -c < "$f") bytes)"; else echo "MISSING $f"; fi
  done
  if [ -d /etc/ssl/certs ]; then echo "ok   /etc/ssl/certs ($(ls /etc/ssl/certs | wc -l) entries)"; else echo "MISSING /etc/ssl/certs"; fi
  echo "shipped data: $(wc -c < /usr/share/ca-certificates/mozilla.crt) bytes"
  echo "-- bundle header:"; head -4 /etc/ssl/certs/ca-certificates.crt 2>&1

  echo "== the store, and one root in full"
  trust list | tail -1
  FP=$(trust list | head -1 | cut -d' ' -f1); echo "picked $FP"
  trust show "$FP" | head -6

  echo "== distrust takes effect and leaves no hashed file behind"
  BEFORE_HASHED=$(ls /etc/ssl/certs | wc -l)
  trust distrust "$FP" --reason "smoke test"; echo "exit=$?"
  sleep 2
  trust list | tail -1
  echo "hashed entries: $BEFORE_HASHED -> $(ls /etc/ssl/certs | wc -l)  (want one fewer)"
  echo "the distrusted root is gone from the socket:"
  trust show "$FP"; echo "exit=$? (want 2)"
  trust status | head -8

  echo "== what is distrusted, and why"
  trust list --distrusted

  echo "== restore, by the same prefix trust list prints"
  trust restore "$FP"; echo "exit=$?"; sleep 2; trust list | tail -1
  echo "hashed entries: $(ls /etc/ssl/certs | wc -l)  (want the original)"
  trust list --distrusted | tail -1

  echo "== add a certificate"
  # A real, valid CA certificate is to hand: one the store already ships.
  # Adding it under our own name exercises the whole path, and the
  # duplicate collapsing is itself the documented behaviour.
  trust show "$FP" | tail -n +8 > /share/one.pem
  head -1 /share/one.pem
  trust add smoke-ca /share/one.pem --purposes ServerAuth,CodeSigning; echo "exit=$?"
  sleep 2; trust status | head -7

  echo "== rubbish is refused and the store survives"
  echo "not a certificate" > /share/junk.pem
  trust add junk-ca /share/junk.pem; echo "exit=$? (want non-zero)"
  trust list | tail -1

  echo "== remove"
  trust remove smoke-ca; echo "exit=$?"; sleep 2; trust status | head -6

  echo "== the registry is the gate, and holds decisions only"
  reg ls 'Machine/System/Trust/Certificates'
  reg get 'Machine/System/Trust'

  echo "== GenerateLinuxTrustFiles 0 removes the files"
  reg set Machine/System/Trust GenerateLinuxTrustFiles dword:0; sleep 2
  for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
    if [ -e "$f" ]; then echo "STILL PRESENT $f"; else echo "ok   gone: $f"; fi
  done
  if [ -e /etc/ssl/certs ]; then echo "STILL PRESENT /etc/ssl/certs"; else echo "ok   gone: /etc/ssl/certs"; fi
  echo "and the socket still serves: $(trust list | tail -1)"
  trust status | tail -4

  echo "== back to 1"
  reg set Machine/System/Trust GenerateLinuxTrustFiles dword:1; sleep 2
  for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
    if [ -f "$f" ]; then echo "ok   back: $f"; else echo "MISSING $f"; fi
  done

  echo "== a real TLS client validates against the rendered store"
  /share/probe-tls 2>&1 || echo "(probe absent)"

  echo "== final status"; trust status
} > /share/trustd-report.txt 2>&1
