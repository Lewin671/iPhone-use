# Connection security

## Implemented boundary

- Both control and MJPEG select an actual USB entry first, then the selected device's paired, connected CoreDevice private IPv6 tunnel. No ordinary LAN address or usbmux Network fallback is accepted. The system provides the wireless pairing/tunnel; this project does not implement its cryptography.
- Every HTTP request to the Mac gateway and WDA requires the private 256-bit Bearer credential. The gateway validates Host and rejects Origin and duplicate Authorization headers. Device HTTP and MJPEG reject Origin and ambiguous authentication headers.
- The gateway authenticates a device connection with a read-only handshake before sending any mutation. Unsecured backends, invalid/missing credentials, broken framing and disconnects fail closed. Already-sent operations are never replayed across transports.
- The patched runner starts no listener without a valid credential. MJPEG sends no frames until a complete, bounded, authenticated GET request arrives; incomplete authentication connections expire.
- Runtime directories are owner-only, outside Git. The credential and launch xctestrun are 600 files. Tokens are absent from tool outputs, source, job argv and normal diagnostics. WDA verbose request logging is disabled.
- Pinning checks both upstream HEAD and the exact authentication patch. Build fingerprints include that patch. A successful legacy WDA /status is not accepted as secure readiness.

## Limits

This is transport authentication, not an app permission or human-approval system. It does not fix input continuation, turn preview pause into a full privacy pause, or change screenshots/telemetry/model data handling. Those remain separate review items.

Bearer authentication does not protect against a fully compromised Mac account: a process with the user's filesystem privileges can read the private credential. No support is provided for direct unencrypted LAN access. On-device listeners retain network reachability for the paired tunnel, but all access requires the credential. Do not manually forward those ports to another network.

## Upgrade

Stop only the plugin-owned old worker, fetch the managed patched source, build and start again. Preserve signing/device configuration and credentials. An externally started stock WDA is not killed or adopted. A missing/malformed credential is an error; do not disable authentication as a recovery step.

The maintained patch is `tooling/wda-auth.patch`, against Appium WDA commit `d17782422d55ff1e5e0ceb74eb1fd509cc0c35b6` (16.14.0). New upstream versions require re-reviewing and rebuilding this patch.

## Physical-device acceptance (not yet completed)

Automated regressions and a generic iOS Simulator build passed during development. Physical signing was blocked by Xcode reporting “No Accounts” and no provisioning profile for the validation runner. This is not evidence that USB/Wi-Fi runtime acceptance passed.

Before relying on this build:

1. Sign and launch the managed patched runner. Confirm READY and actual `transport` over USB and then Wi-Fi, including live MJPEG.
2. Verify missing/wrong credentials on Mac and on-device control/stream endpoints yield no screen data or action; valid credentials work through the selected transport.
3. Check ordinary LAN access has no unauthenticated bypass, including the stream port and /status.
4. Exercise plug/unplug, lock/unlock and runner restart. An uncertain action must not be repeated automatically. Reconnect and observe actual state before continuing.
5. Confirm secrets are absent from model results and normal logs. Keep native diagnostics and signed builds private.
