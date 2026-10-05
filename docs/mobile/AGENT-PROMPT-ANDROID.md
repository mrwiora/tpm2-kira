# Agent prompt — build the tpm2-kira verifier app for Android

> Hand this file to a coding agent together with a checkout of the
> tpm2-kira repository. The iOS counterpart is
> [AGENT-PROMPT-IOS.md](AGENT-PROMPT-IOS.md); both implement the same
> protocol, [docs/PROTOCOL-BLE.md](../PROTOCOL-BLE.md), through the same Go core.

---

## Your task

Build **"Kira"**, an Android app that acts as the *verifier* for
tpm2-kira machines. Before the user types their disk passphrase on a Linux
laptop, the laptop advertises over Bluetooth LE; the app connects, lets the
machine's TPM prove what it booted, shows the user a verdict they can act
on, and returns a signed receipt.

You build the Android shell: BLE central, hardware-backed key, biometric
prompt, storage, UI. **You do not implement any protocol cryptography or
any trust decision.** Those live in the Go core `kiracore`, which you compile
with gomobile and call.

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

1. **Never decide trust in Kotlin.** Show `verdict.state`, `reasons`,
   `explanation`; pass the user's choice to `Session.decide`. No PCR
   comparisons, no "if digest equals" logic, no re-implementation of any
   message, hash, signature check or handshake.
2. **Always write every fragment of every `Step`, in order, even when
   `step.err()` is non-empty.** A failing step carries the Error message that
   tells the machine to stop. Whether the session ended is
   `session.finished()`.
3. **No BLE bonding.** Never call `createBond()`. Never require encryption on
   a characteristic. Ignore pairing prompts (the machine refuses pairing).
4. **The anchor key is hardware-backed, non-exportable and needs a fresh
   biometric authentication for every signature** (§11.2). A user who hands
   over an unlocked phone must not be able to attest a machine.
5. **Show only machines the user enrolled**, matched with
   `Kiracore.matchAdvertisement`. Show ENROL-mode machines only while the user
   is on the enrolment screen.
6. Do not show PCR hex as the primary information; put it behind "Details".
7. `kiratest` (the demo machine) goes into `debugImplementation` /
   `androidTestImplementation` only. It must never be in a release APK.

## Toolchain

- Kotlin 2.x, Jetpack Compose (Material 3), coroutines/Flow, Hilt or manual DI.
- `minSdk 28`, `targetSdk` current. Gradle Kotlin DSL, version catalog.
- Go ≥ 1.24, Android SDK + NDK, `gomobile`:

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
# from the tpm2-kira checkout:
gomobile bind -target=android -androidapi 28 -o app/libs/kiracore.aar ./mobile/kiracore
gomobile bind -target=android -androidapi 28 -o app/libs/kiratest.aar  ./mobile/kiratest   # tests only
```

Add a Gradle task (or script `scripts/build-core.sh`) that rebuilds the
`.aar` files from a pinned tpm2-kira commit, and document it in the README.
Generated Java API (verified with gobind — note that Go `int` is Java `long`):

```java
// package kiracore
Kiracore.newEnrolSession(String cfgJSON, byte[] noisePriv) throws Exception -> Session
Kiracore.newAttestSession(String cfgJSON, byte[] noisePriv, String recordJSON) throws Exception -> Session
Kiracore.generateNoiseKey() throws Exception -> byte[]
Kiracore.matchAdvertisement(byte[] serviceData, String recordJSON) -> boolean
Kiracore.advertisementFlags(byte[] serviceData) -> long
Kiracore.recordSummary(String recordJSON) throws Exception -> String
Kiracore.protocolVersion(), Kiracore.schemaVersion() -> long
Kiracore.ServiceUUID, RXCharUUID, TXCharUUID, InfoUUID          // String constants
Kiracore.DecisionApproveOnce / DecisionApproveRemember / DecisionReject, AdvFlagEnrol / AdvFlagAttest  // long

Session: setMaxFragment(long) throws Exception; start(); onNotification(byte[]); confirmSAS(boolean);
         provideAnchorKey(byte[]); pendingTBS() -> byte[]; provideSignature(byte[]);
         decide(long, String); requestEventlog(); eventlog() -> byte[]; abort(String);
         finished(); succeeded(); recordJSON()      // all Step-returning calls are non-throwing
Step:    fragmentCount() -> long; fragment(long) -> byte[]; eventCount() -> long; event(long) -> String (JSON); err() -> String
```

## Architecture

```
app/
├── core/          KiraCore.kt        — thin Kotlin facade over kiracore (Step → data classes, JSON → sealed Event)
├── ble/           BleScanner.kt      — scan with service-UUID filter, parse service data
│                  GattLink.kt        — one connection: MTU, discovery, CCCD, serialized write queue, notifications as Flow
├── session/       SessionRunner.kt   — drives one Session over one GattLink (the loop below)
├── keys/          AnchorKeys.kt      — StrongBox/TEE EC keys per machine, BiometricPrompt signing
│                  NoiseKeyStore.kt   — the static Noise key, encrypted at rest
├── data/          MachineRepository.kt — machine records (JSON from the core), encrypted, no backup
├── ui/            screens (below), ViewModels
└── service/       AttestationService.kt — foreground service (type connectedDevice) during a session
```

Run **all** calls into `Session` on one single-threaded dispatcher
(`Dispatchers.Default.limitedParallelism(1)`), in arrival order. The core is
thread-safe, but ordering matters: a notification must be fed before a later
UI decision that depends on it.

### The session loop

```kotlin
suspend fun run(session: Session, link: GattLink, ui: SessionUi) {
    session.setMaxFragment(link.mtu - 3L)
    handle(session.start())
    link.notifications.collect { value -> handle(session.onNotification(value)) }  // until finished
}

suspend fun handle(step: Step) {
    for (i in 0 until step.fragmentCount()) link.write(step.fragment(i))   // ALWAYS, even if err() != ""
    for (i in 0 until step.eventCount()) when (val e = Event.parse(step.event(i))) {
        is Event.Sas            -> ui.showSas(e.sas) { match -> handle(session.confirmSAS(match)) }
        is Event.NeedAnchorKey  -> handle(session.provideAnchorKey(anchorKeys.create(e.deviceId)))
        is Event.NeedSignature  -> handle(session.provideSignature(anchorKeys.sign(deviceId, session.pendingTBS(), e.purpose)))
        is Event.Hello          -> ui.connectedTo(e.friendlyName)
        is Event.Verdict        -> ui.showVerdict(e.verdict, e.needsDecision, e.eventlogAvailable) { d, typedName -> handle(session.decide(d, typedName)) }
        is Event.Eventlog       -> ui.eventlogProgress(e.received, e.total, e.complete)
        is Event.Enrolled       -> repo.save(e.recordJson)
        is Event.RecordUpdated  -> repo.replace(e.recordJson)
        is Event.ReceiptAck     -> ui.machineAnswered(e.result, e.message)
        is Event.Done           -> link.disconnect()
        is Event.Error          -> { ui.error(e.code, e.message); link.disconnect() }
    }
    if (step.err().isNotEmpty() && !session.finished()) ui.recoverableError(step.err())
}
```

User actions (SAS confirmation, decisions, biometric results) arrive
asynchronously; post them to the same dispatcher and call `handle` with the
returned Step. If the user leaves the screen, call `session.abort("cancelled")`,
write its fragments, then disconnect.

## BLE details

- **Permissions:** API 31+: `BLUETOOTH_SCAN` (with
  `android:usesPermissionFlags="neverForLocation"`) and `BLUETOOTH_CONNECT`.
  API 28–30: `ACCESS_FINE_LOCATION` + `BLUETOOTH` + `BLUETOOTH_ADMIN`. Ask at
  first use with a rationale screen. Handle Bluetooth off
  (`ACTION_REQUEST_ENABLE`).
- **Scan:** `BluetoothLeScanner.startScan(listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE)).build()), ScanSettings(SCAN_MODE_LOW_LATENCY), cb)`.
  Service data: `scanRecord.getServiceData(ParcelUuid(SERVICE))` (13 bytes).
  Flags: `Kiracore.advertisementFlags`. Label: try every stored record with
  `Kiracore.matchAdvertisement`. Stop scanning before connecting.
- **Connect:** `device.connectGatt(ctx, false, cb, BluetoothDevice.TRANSPORT_LE)`,
  then `requestConnectionPriority(CONNECTION_PRIORITY_HIGH)`,
  `requestMtu(517)`, wait for `onMtuChanged(mtu)`, `discoverServices()`.
- **Read INFO** (§3.2): refuse with "update needed" if protocol ≠ 1 or schema
  > `Kiracore.schemaVersion()`. Check mode: 1 enrol, 2 attest.
- **Notifications:** `setCharacteristicNotification(tx, true)` and write
  `ENABLE_NOTIFICATION_VALUE` to the CCCD (`0x2902`); wait for
  `onDescriptorWrite` **before** `session.start()`.
- **Writes:** `WRITE_TYPE_NO_RESPONSE` on RX. Android allows **one GATT
  operation at a time**: keep a write queue and send the next fragment only
  after `onCharacteristicWrite`. On API 33+ use
  `writeCharacteristic(char, value, writeType)` and check its return code;
  retry `ERROR_GATT_WRITE_REQUEST_BUSY` with backoff.
- **Notifications in:** API 33+ `onCharacteristicChanged(gatt, char, value)`;
  older: read `char.value` immediately inside the callback (it is reused).
  Preserve order; never drop.
- **Disconnects** at any point end the session: show "connection lost", do
  not retry automatically while a decision is pending; offer "Try again".
- Always `gatt.close()` after disconnect. Handle status 133 with one
  reconnect attempt.

## Keys

### Static Noise key (one per installation)

`Kiracore.generateNoiseKey()` at first launch. Encrypt with an AES-256-GCM key
from AndroidKeyStore (no user auth) and store the ciphertext in DataStore.
Generate a `verifier_id` (16 random bytes, hex) at the same time and store it
next to it. Config JSON for sessions:
`{"verifier_id":"<hex>","verifier_name":"<Build.MODEL>","policy_id":"default","receipt_ttl_seconds":300}`.

### Anchor key (one per machine, created at `need_anchor_key`)

```kotlin
KeyGenParameterSpec.Builder("kira-anchor-$deviceIdHex", KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .setInvalidatedByBiometricEnrollment(true)
    .setIsStrongBoxBacked(true)          // catch StrongBoxUnavailableException → retry without
    .build()
```

Hand `keyPair.public.encoded` (SPKI DER, 91 bytes) to `provideAnchorKey`.
Record whether StrongBox was used and show it in machine details.

**Signing** (`need_signature`): `Signature.getInstance("SHA256withECDSA")`,
`initSign(privateKey)`, wrap in `BiometricPrompt.CryptoObject`, authenticate
with `BIOMETRIC_STRONG`; in `onAuthenticationSucceeded` call
`update(session.pendingTBS())` and `sign()` → DER bytes → `provideSignature`.
Do **not** hash first, do **not** convert to raw r‖s. Prompt text by purpose:
`enrol_accept` → "Bind <machine> to this phone", `receipt` with verdict 1 →
"Confirm <machine> booted unchanged", verdict 2 → "Approve the changed boot of
<machine>". If the user cancels biometry, call `session.abort("biometric cancelled")`.

Optionally attach the Key Attestation certificate chain to the machine details
screen (proves StrongBox/TEE); it is informational.

## Storage

- `MachineRepository`: one encrypted file (or DataStore entry) per machine,
  holding the exact `record` JSON from `enrolled` / `record_updated`. Never edit
  the JSON; parse display fields via `Kiracore.recordSummary`.
- `android:allowBackup="false"`, `dataExtractionRules` excluding everything.
- Deleting a machine: delete the record and its anchor key; tell the user to
  run `sudo tpm2-kira attest unenrol` on the machine.

## Screens

1. **Onboarding** — what Kira does (one paragraph from PROTOCOL-BLE.md §1.1),
   permissions, biometric enrolment check (refuse to continue without
   `BIOMETRIC_STRONG`).
2. **Machines** — enrolled machines with last-attested time; FAB "Enrol a
   machine"; a banner "<machine> is asking for attestation" when its
   advertisement is seen (tap → session).
3. **Enrol** — instructions ("run `sudo tpm2-kira attest enrol` on the
   machine"), list of ENROL-mode advertisements, then the **SAS screen**: the
   six digits huge, "Does this match the number on your computer's screen?"
   *Matches* / *Does not match*. Then biometric "Bind", then success.
4. **Attest** — progress (connecting → verifying), then the verdict:
   - `match`: green check, "<name> — unchanged since <last_attested>",
     biometric prompt runs automatically to sign; then "Receipt delivered".
   - `changed`: amber, `explanation` as the headline, the diff list
     (description per PCR; hex behind "Details"), optional "Show event log"
     (`requestEventlog`, progress bar), buttons **Approve once**, **Approve
     and remember**, **Reject**.
   - `failed`: red, "Attestation failed" + every hard reason in plain words,
     **Reject** as the primary button; "Approve anyway" hidden behind an
     overflow and requiring the user to type the machine's name (pass it as
     `confirmName`).
   - After `receipt_ack`: show the machine's answer (result 1 = "The machine
     accepted the receipt"; 2 = "The machine says the receipt is not from its
     enrolled phone"; 4 = "Rejection delivered").
5. **Machine details** — name, enrolled at, profiles (name, added by, valid
   until), key storage (StrongBox/TEE), delete.

Map reason codes (PROTOCOL-BLE.md §10.4) to localized strings in one table.

## Background behaviour

Sessions run in a foreground service with
`android:foregroundServiceType="connectedDevice"` and an ongoing notification
("Verifying <machine>…"). Scanning for "is asking" banners runs only while the
app is in the foreground; optionally offer a `PendingIntent`-based background
scan (`startScan(filters, settings, pendingIntent)`) with the service-UUID
filter that posts a notification "<machine> is waiting for attestation".

## Testing

1. **Unit tests** (JVM): Event JSON parsing for every event type in
   PROTOCOL-BLE.md §10.3; the write queue (ordering, busy retry); reason-code
   mapping.
2. **Instrumented tests with the demo machine** (`kiratest.aar`): connect a
   `SessionRunner` to a fake `GattLink` backed by `DemoMachine.write` /
   `DemoMachine.nextNotification`, with a software anchor key replacing
   `AnchorKeys` (inject via DI). Cover: enrolment (assert the SAS equals
   `lastSAS()`), `match` (`nextBoot()`), `changed` + approve-and-remember
   (`changePCR(4)`), the next attestation matching the remembered profile,
   `failed` (`rollbackResetCount()`) + reject, user abort mid-session, MTU 23
   and 517. Assert `demo.outcome(5000)` each time
   (`receipt: verdict=ok authentic=true`, …).
3. **Compose UI tests** for the three verdict screens with fixed JSON.
4. **Real hardware checklist** (document results in `TESTING.md`): a Linux
   machine with a Bluetooth adapter running `sudo tpm2-kira attest enrol` and
   `sudo tpm2-kira attest gate`; Pixel (StrongBox) and one non-Pixel device;
   Bluetooth off/on mid-session; app killed mid-session; two machines in range.

## Acceptance criteria

- Enrolment and attestation work against `DemoMachine` in instrumented tests
  for all three verdict states, and against a real machine.
- No Kotlin code compares PCRs, parses protocol messages or verifies
  signatures.
- Every Step's fragments are written, including on error (unit-tested).
- Anchor keys are non-exportable, StrongBox when available, biometric per use
  (verified with `KeyInfo`).
- Release build contains no `kiratest` classes (verify with `apkanalyzer`).
- Lint clean, no `allowBackup`, no bonding calls.

## Extension point: salt release (later)

When the machine advertises `CAP_RELEASE_FACTOR` (Hello capabilities), a
future core version will emit an event after `receipt_ack` asking the app to
release the stored factor blob for hashpwd2 (PROTOCOL-BLE.md §7.3.7). Keep the
session loop event-driven so this is one more `when` branch, and keep
`MachineRepository` able to store one more opaque blob per machine.

## Deliverables

A Gradle project in `android/` (or a separate repository, as instructed):
source, the core build script, unit + instrumented tests, `README.md` (build,
architecture, threat notes copied from PROTOCOL-BLE.md §13), `TESTING.md`.
