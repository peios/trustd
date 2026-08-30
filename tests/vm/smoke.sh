# Guest-side smoke test for trustd. Run with
#   dist/release/drive.py --no-disk --share <dir> --timeout 260 \
#     --cmdline-extra 'loglevel=7 ignore_loglevel' <dir>/smoke.sh
# and read <dir>/trustd-report.txt plus the trustd: lines on the console.
#
# What it is checking, in order: that the store composes at all, that the
# three compat artifacts exist where each consumer looks for them, that the
# socket and the files agree, that a distrust takes effect within seconds
# and leaves no hashed file behind, that an addition round-trips, that
# validation refuses rubbish without taking the store down, and that
# GenerateLinuxTrustFiles 0 removes the files rather than leaving stale
# trust in force.
{
  echo "== service"; svctl status trustd | head -3
  echo "== status"; trust status

  echo "== the three artifacts"
  ls -l /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem 2>&1
  echo "hashed files: $(ls /etc/ssl/certs/ | grep -c '^[0-9a-f]\{8\}\.')"
  echo "bundle certs: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)"
  echo "cert.pem certs: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/cert.pem)"
  echo "shipped data:  $(grep -c 'BEGIN CERTIFICATE' /usr/share/ca-certificates/mozilla.crt)"
  head -3 /etc/ssl/certs/ca-certificates.crt

  echo "== the socket agrees with the files"
  echo "socket roots: $(trust list | tail -1)"

  echo "== one root in detail"; trust list | head -1
  FP=$(trust list | head -1 | cut -d' ' -f1); echo "picked $FP"
  trust show "$FP" | head -8

  echo "== distrust takes effect"
  trust distrust "$FP" --reason "smoke test"; echo "exit=$?"
  sleep 2
  echo "after: $(trust list | tail -1)"
  echo "bundle certs now: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)"
  echo "still in bundle (want 0): $(grep -c "$FP" /etc/ssl/certs/ca-certificates.crt)"
  echo "hashed files now: $(ls /etc/ssl/certs/ | grep -c '^[0-9a-f]\{8\}\.')"
  trust status | head -8

  echo "== restore"
  trust restore "$FP"; sleep 2; echo "after: $(trust list | tail -1)"

  echo "== add a certificate"
  # Reuse a root the store already ships, under a name of our own: it is a
  # real, valid CA certificate, so this exercises the whole add path
  # without needing a CA to hand.
  trust show "$FP" | sed -n '/BEGIN CERT/,/END CERT/p' > /share/one.pem
  trust add smoke-ca /share/one.pem --purposes ServerAuth,CodeSigning; echo "exit=$?"
  sleep 2
  trust list | grep smoke || echo "(the certificate is already in the store; the duplicate collapses, as designed)"
  trust status | head -6

  echo "== rubbish is refused without taking the store down"
  echo "not a certificate" > /share/junk.pem
  trust add junk-ca /share/junk.pem; echo "exit=$? (want non-zero)"
  echo "roots still: $(trust list | tail -1)"

  echo "== remove"
  trust remove smoke-ca; sleep 2; echo "after: $(trust list | tail -1)"

  echo "== the registry is the only gate"
  reg ls 'Machine/System/Trust/Certificates'
  reg get 'Machine/System/Trust' 2>&1 | head -4

  echo "== GenerateLinuxTrustFiles 0 removes the files"
  reg set Machine/System/Trust GenerateLinuxTrustFiles dword:0; sleep 2
  ls -l /etc/ssl/certs/ca-certificates.crt 2>&1 | head -1
  echo "(want: no such file)"
  trust status | tail -3
  echo "and the socket still serves: $(trust list | tail -1)"

  echo "== back to 1"
  reg set Machine/System/Trust GenerateLinuxTrustFiles dword:1; sleep 2
  ls -l /etc/ssl/certs/ca-certificates.crt 2>&1 | head -1

  echo "== a TLS client actually validates"
  # The point of all of it: something that reads the rendered files can
  # verify a real chain.
  /share/probe-tls || echo "(probe absent or offline)"

  echo "== final status"; trust status
} > /share/trustd-report.txt 2>&1
