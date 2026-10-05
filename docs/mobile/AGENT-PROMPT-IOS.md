# Agent prompt — build the tpm2-kira verifier app for iOS

> Hand this file to a coding agent together with a checkout of the
> tpm2-kira repository. The Android counterpart is
> [AGENT-PROMPT-ANDROID.md](AGENT-PROMPT-ANDROID.md); both implement the same
> protocol, [docs/PROTOCOL-BLE.md](../PROTOCOL-BLE.md), through the same Go core.

---

## Your task

Build **"Kira"**, an iOS app that acts as the *verifier* for tpm2-kira
machines. Before the user types their disk passphrase on a Linux laptop, the
laptop advertises over Bluetooth LE; the app connects, lets the machine's TPM
prove what it booted, shows the user a verdict they can act on, and returns a
signed receipt.

You build the iOS shell: BLE central, Secure Enclave key, Face ID / Touch ID,
storage, UI. **You do not implement any protocol cryptography or any trust
decision.** Those live in the Go core `kiracore`, which you compile with
gomobile into an `.xcframework` and call.

## Read first, in this order

1. `docs/PROTOCOL-BLE.md` — **the normative contract.** §3 (GATT), §10
   (core API, events, verdict), §11 (keys), §13 (requirements checklist)
   are the parts you implement against. Where this prompt and that document
   disagree, the document wins; report the discrepancy.
2. `docs/PLAN-BLE.md` §1, §5.3, §6 — the user story, enrolment confirmation,
   the three verdict states and what the user sees.
3. `docs/PLAN-FACTORRELEASE.md` §1, §4 — a future step (salt release for
   hashpwd2) that your session flow must be able to grow into. Do not
   implement it now.
4. `mobile/kiracore/kiracore.go` and `mobile/kiratest/kiratest.go` — the Go
   API you call.

## Non-negotiable rules

1. **Never decide trust in Swift.** Show `verdict.state`, `reasons`,
   `explanation`; pass the user's choice to `session.decide`. No PCR
   comparisons, no digest checks, no re-implementation of any message, hash,
   signature check or handshake.
2. **Always write every fragment of every `KiracoreStep`, in order, even when
   `step.err()` is non-empty.** A failing step carries the Error message that
   tells the machine to stop. Whether the session ended is `session.finished()`.
3. **No pairing.** Never access characteristics that would trigger pairing;
   the machine refuses it, and the protocol does not need it.
4. **The anchor key lives in the Secure Enclave, is non-exportable and needs
   a fresh biometric authentication for every signature** (§11.2). A user who
   hands over an unlocked phone must not be able to attest a machine.
5. **Show only machines the user enrolled**, matched with
   `KiracoreMatchAdvertisement`. Show ENROL-mode machines only while the user
   is on the enrolment screen.
6. Do not show PCR hex as the primary information; put it behind "Details".
7. `Kiratest.xcframework` (the demo machine) is linked into the test targets
   and a Debug-only demo mode, never into Release.

## Toolchain

- Swift 6 (strict concurrency), SwiftUI, iOS 16+, Xcode current.
  CoreBluetooth, CryptoKit, LocalAuthentication, Security.
- Go ≥ 1.24, `gomobile`:

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
# from the tpm2-kira checkout:
gomobile bind -target=ios,iossimulator -o Frameworks/Kiracore.xcframework ./mobile/kiracore
gomobile bind -target=ios,iossimulator -o Frameworks/Kiratest.xcframework ./mobile/kiratest   # tests only
```

Add `scripts/build-core.sh` that rebuilds both frameworks from a pinned
tpm2-kira commit, and document it. Generated Objective-C API (verified with
gobind; Go `int` is `long`, `[]byte` is `NSData`):

```objc
KiracoreSession* KiracoreNewEnrolSession(NSString* cfgJSON, NSData* noisePriv, NSError** error);
KiracoreSession* KiracoreNewAttestSession(NSString* cfgJSON, NSData* noisePriv, NSString* recordJSON, NSError** error);
NSData*  KiracoreGenerateNoiseKey(NSError** error);
BOOL     KiracoreMatchAdvertisement(NSData* serviceData, NSString* recordJSON);
long     KiracoreAdvertisementFlags(NSData* serviceData);
NSString* KiracoreRecordSummary(NSString* recordJSON, NSError** error);
long KiracoreProtocolVersion(void), KiracoreSchemaVersion(void);
NSString* const KiracoreServiceUUID, KiracoreRXCharUUID, KiracoreTXCharUUID, KiracoreInfoUUID;
const long KiracoreDecisionApproveOnce, KiracoreDecisionApproveRemember, KiracoreDecisionReject,
           KiracoreAdvFlagEnrol, KiracoreAdvFlagAttest;

@interface KiracoreSession
- (BOOL)setMaxFragment:(long)n error:(NSError**)error;
- (KiracoreStep*)start;   - (KiracoreStep*)onNotification:(NSData*)fragment;
- (KiracoreStep*)confirmSAS:(BOOL)match;   - (KiracoreStep*)provideAnchorKey:(NSData*)spkiDER;
- (NSData*)pendingTBS;    - (KiracoreStep*)provideSignature:(NSData*)derSig;
- (KiracoreStep*)decide:(long)decision confirmName:(NSString*)name;
- (KiracoreStep*)requestEventlog;   - (NSData*)eventlog;   - (KiracoreStep*)abort:(NSString*)reason;
- (BOOL)finished;  - (BOOL)succeeded;  - (NSString*)recordJSON;
@interface KiracoreStep
- (long)fragmentCount;  - (NSData*)fragment:(long)i;  - (long)eventCount;  - (NSString*)event:(long)i;  - (NSString*)err;
```

In Swift these appear as `KiracoreNewEnrolSession(cfg, noise, &error)`,
`session.confirmSAS(true)`, `step.fragment(i)`, etc. Wrap them in a small
Swift facade so the rest of the app never touches the generated types.

## Architecture

```
Kira/
├── Core/        KiraCore.swift        — facade: Step → struct, event JSON → enum Event (Codable)
├── BLE/         Central.swift         — CBCentralManager (restoration identifier), scanning with the service UUID
│                GattLink.swift        — one CBPeripheral: discovery, notify, write-without-response flow control
├── Session/     SessionRunner.swift   — an actor driving one session over one GattLink (the loop below)
├── Keys/        AnchorKeys.swift      — Secure Enclave keys per machine (CryptoKit), LAContext
│                NoiseKeyStore.swift   — static Noise key in the Keychain
├── Data/        MachineStore.swift    — machine records (JSON from the core), file protection complete, no backup
├── UI/          SwiftUI screens and @Observable models
└── Demo/        DemoLink.swift        — Debug-only GattLink backed by KiratestDemoMachine
```

Make `SessionRunner` an `actor`: it owns the `KiracoreSession` and processes
inputs (notifications, user actions, biometric results) strictly in order.
CoreBluetooth delegate callbacks hop onto the actor.

### The session loop

```swift
actor SessionRunner {
    func run() async throws {
        try session.setMaxFragment(link.maxWriteLength)       // maximumWriteValueLength(for: .withoutResponse)
        await handle(session.start()!)
        for await value in link.notifications { await handle(session.onNotification(value)!) }
    }

    func handle(_ step: KiracoreStep) async {
        for i in 0..<step.fragmentCount() { await link.write(step.fragment(i)!) }   // ALWAYS, even if err() != ""
        for i in 0..<step.eventCount() {
            switch Event(json: step.event(i)) {
            case .sas(let code):              ui.showSAS(code)            // → confirm(match:) → handle(session.confirmSAS(match))
            case .needAnchorKey(let dev, _):  await handle(session.provideAnchorKey(try anchorKeys.create(for: dev))!)
            case .needSignature(let purpose, let verdict):
                                              await handle(session.provideSignature(try await anchorKeys.sign(session.pendingTBS()!, device, purpose, verdict))!)
            case .hello(let name):            ui.connected(to: name)
            case .verdict(let v, let needsDecision, let logAvailable):
                                              ui.show(v, needsDecision, logAvailable)  // → decide(d, typedName) → handle(session.decide(d, confirmName: typedName))
            case .eventlog(let rx, let total, let complete): ui.eventlog(rx, total, complete)
            case .enrolled(let record):       try store.save(record)
            case .recordUpdated(let record):  try store.replace(record)
            case .receiptAck(let result, let msg): ui.machineAnswered(result, msg)
            case .done:                       link.disconnect()
            case .error(let code, let msg):   ui.error(code, msg); link.disconnect()
            }
        }
        if !step.err().isEmpty && !session.finished() { ui.recoverable(step.err()) }
    }
}
```

If the user leaves the screen or cancels Face ID, call
`session.abort("cancelled")`, write its fragments, then disconnect.

## BLE details

- **Info.plist:** `NSBluetoothAlwaysUsageDescription`, `NSFaceIDUsageDescription`,
  `UIBackgroundModes` = `bluetooth-central`.
- **Central:** `CBCentralManager(delegate:queue:options: [CBCentralManagerOptionRestoreIdentifierKey: "kira.central"])`.
  Handle `.poweredOff`, `.unauthorized`, `.unsupported` with clear UI.
- **Scan:** `scanForPeripherals(withServices: [CBUUID(string: KiracoreServiceUUID)], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])`.
  **Always pass the service UUID** — iOS scans in the background only with an
  explicit filter. Service data:
  `(advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data])?[serviceUUID]`
  (13 bytes; may be missing in the background — then connect and try each
  stored record, PROTOCOL-BLE.md §2.2). Identify peripherals by what the
  session says, never by `peripheral.identifier` alone (it is per-app and
  can change).
- **Connect:** `connect(peripheral)`, `discoverServices([service])`,
  `discoverCharacteristics([rx, tx, info], for:)`.
- **Read INFO** (§3.2): refuse with "update needed" if protocol ≠ 1 or schema
  > `KiracoreSchemaVersion()`. Check mode: 1 enrol, 2 attest.
- **MTU:** iOS negotiates it. Use
  `peripheral.maximumWriteValueLength(for: .withoutResponse)` as the fragment
  size (it is already MTU − 3; typically 182).
- **Notifications:** `setNotifyValue(true, for: tx)`; wait for
  `didUpdateNotificationStateFor` with `isNotifying == true` **before**
  `session.start()`.
- **Writes:** `writeValue(fragment, for: rx, type: .withoutResponse)` only
  while `peripheral.canSendWriteWithoutResponse`; otherwise suspend until
  `peripheralIsReady(toSendWriteWithoutResponse:)`. Preserve order.
- **Notifications in:** `didUpdateValueFor characteristic:` → copy
  `characteristic.value` immediately → feed to the actor in order.
- **Disconnects** end the session: show "connection lost"; offer "Try again".
- **State restoration:** implement `willRestoreState`; if a session was in
  progress, abort it cleanly — never resume a half-finished session.

## Keys

### Static Noise key (one per installation)

`KiracoreGenerateNoiseKey()` at first launch; store in the Keychain as a
generic password, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
`kSecAttrSynchronizable = false`. Generate a `verifier_id` (16 random bytes,
hex) at the same time. Config JSON for sessions:
`{"verifier_id":"<hex>","verifier_name":"<UIDevice.current.name or model>","policy_id":"default","receipt_ttl_seconds":300}`.

### Anchor key (one per machine, created at `need_anchor_key`)

Use CryptoKit:

```swift
let access = SecAccessControlCreateWithFlags(nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet], nil)!
let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
// Persist key.dataRepresentation (an opaque, Secure-Enclave-bound blob) in the
// Keychain under "kira-anchor-<deviceIdHex>", ThisDeviceOnly, not synchronizable.
session.provideAnchorKey(key.publicKey.derRepresentation)   // SPKI DER, 91 bytes
```

**Signing** (`need_signature`): create an `LAContext`, set
`localizedReason` by purpose (`enrol_accept` → "Bind <machine> to this
iPhone"; `receipt` with verdict 1 → "Confirm <machine> booted unchanged";
verdict 2 → "Approve the changed boot of <machine>"), restore the key with
`SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:authenticationContext:)`,
then `try key.signature(for: session.pendingTBS())` — CryptoKit hashes with
SHA-256 — and pass `signature.derRepresentation` to `provideSignature`.
Do **not** pre-hash, do **not** use `rawRepresentation`. If the user cancels,
call `session.abort("biometric cancelled")`.

Require `SecureEnclave.isAvailable` and biometry enrolled; otherwise refuse
enrolment with an explanation (the simulator has no Secure Enclave — tests
inject a software key, see Testing).

## Storage

- `MachineStore`: one file per machine in Application Support holding the
  exact `record` JSON from `enrolled` / `record_updated`, written with
  `.completeFileProtection`, `isExcludedFromBackup = true`. Never edit the
  JSON; parse display fields via `KiracoreRecordSummary`.
- Deleting a machine: delete the record and its Keychain items; tell the user
  to run `sudo tpm2-kira attest unenrol` on the machine.

## Screens

1. **Onboarding** — what Kira does (one paragraph from PROTOCOL-BLE.md §1.1),
   Bluetooth permission, Face ID / Touch ID check.
2. **Machines** — enrolled machines with last-attested time; "Enrol a
   machine"; a banner "<machine> is asking for attestation" when its
   advertisement is seen (tap → session).
3. **Enrol** — instructions ("run `sudo tpm2-kira attest enrol` on the
   machine"), ENROL-mode advertisements, then the **SAS screen**: six large
   digits, "Does this match the number on your computer's screen?" *Matches* /
   *Does not match*. Then Face ID "Bind", then success.
4. **Attest** — progress, then the verdict:
   - `match`: green checkmark, "<name> — unchanged since <last_attested>";
     Face ID runs automatically to sign; then "Receipt delivered".
   - `changed`: amber, `explanation` as the headline, the diff list
     (description per PCR; hex behind "Details"), optional "Show event log"
     (`requestEventlog`, progress), buttons **Approve once**, **Approve and
     remember**, **Reject**.
   - `failed`: red, "Attestation failed" + every hard reason in plain words,
     **Reject** as the primary button; "Approve anyway" behind a menu,
     requiring the user to type the machine's name (passed as `confirmName`).
   - After `receipt_ack`: the machine's answer (1 accepted; 2 "not from its
     enrolled phone"; 4 rejection delivered).
5. **Machine details** — name, enrolled at, profiles, delete.

Map reason codes (PROTOCOL-BLE.md §10.4) to localized strings in one table
(String Catalog).

## Background behaviour

With `bluetooth-central` and a service-UUID scan, iOS can deliver discoveries
in the background; post a local notification "<machine> is waiting for
attestation" (only for matched machines). The session itself needs Face ID,
so it runs with the app in the foreground; when launched from the
notification, connect immediately.

## Testing

1. **Unit tests** (XCTest/Swift Testing): `Event` decoding for every event
   type in PROTOCOL-BLE.md §10.3; the write flow control (ordering, waiting
   for readiness); reason-code mapping.
2. **Integration tests with the demo machine** (`Kiratest.xcframework`): a
   `DemoLink` implementing the `GattLink` protocol with
   `KiratestDemoMachine.write(_:)` / `nextNotification(_:)`, and a software
   P-256 key (`P256.Signing.PrivateKey`) replacing `AnchorKeys` (protocol +
   injection). Cover: enrolment (SAS equals `lastSAS()`), `match`
   (`nextBoot()`), `changed` + approve-and-remember (`changePCR(4)`), the
   following attestation matching the remembered profile, `failed`
   (`rollbackResetCount()`) + reject, abort mid-session, fragment sizes 20 and
   182. Assert `demo.outcome(5000)` each time
   (`receipt: verdict=ok authentic=true`, …). These run on the simulator.
3. **SwiftUI previews and snapshot/UI tests** for the three verdict screens
   with fixed JSON.
4. **Real hardware checklist** (`TESTING.md`): a Linux machine with a
   Bluetooth adapter running `sudo tpm2-kira attest enrol` and
   `sudo tpm2-kira attest gate`; an iPhone with Face ID and one with Touch ID;
   background discovery; Bluetooth toggled mid-session; app killed
   mid-session; two machines in range.

## Acceptance criteria

- Enrolment and attestation work against `KiratestDemoMachine` for all three
  verdict states (simulator), and against a real machine (device).
- No Swift code compares PCRs, parses protocol messages or verifies
  signatures.
- Every Step's fragments are written, including on error (unit-tested).
- Anchor keys are Secure Enclave keys with `.biometryCurrentSet`; signing
  without Face ID fails (tested on device).
- Release build does not link `Kiratest` (check the build settings and the
  binary's symbols).
- Swift 6 strict concurrency, no warnings.

## Extension point: salt release (later)

When the machine advertises `CAP_RELEASE_FACTOR` (Hello capabilities), a
future core version will emit an event after `receipt_ack` asking the app to
release the stored factor blob for hashpwd2 (PROTOCOL-BLE.md §7.3.7). Keep the
session loop event-driven so this is one more `case`, and keep `MachineStore`
able to hold one more opaque blob per machine.

## Deliverables

An Xcode project in `ios/` (or a separate repository, as instructed): source,
the core build script, unit + integration tests, `README.md` (build,
architecture, threat notes from PROTOCOL-BLE.md §13), `TESTING.md`.
