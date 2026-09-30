# PLAN-PCRLOCK.md — should tpm2-kira use systemd-pcrlock?

Status: **investigation, with a recommendation**. Nothing implemented.

Short answer: **not as a policy mechanism, and not yet as a PCR source.** The
investigation did turn up one change worth making that came out of looking at
pcrlock but does not need it, and that is the recommendation at the end.

---

## 1. What pcrlock actually is

Verified on this host (systemd 262, Arch), from `/usr/lib/systemd/systemd-pcrlock`
and `systemd-pcrlock(8)`:

> Note: this command is **experimental** for now. While it is likely to become a
> regular component of systemd, it might still change in behaviour and interface.

It takes as input:

- the UEFI firmware event log, `/sys/kernel/security/tpm0/binary_bios_measurements`
- the **userspace** event log, `/run/log/systemd/tpm2-measure.log`
- the current PCR state of the TPM
- component definition files, `/var/lib/pcrlock.d/*.pcrlock`, each describing the
  expected measurements for one boot component, **permitting alternative variants**
  — which is how several kernel or bootloader versions are blessed at once

From those it predicts future PCR values and converts the prediction into a policy
of `TPM2_PolicyPCR` and `TPM2_PolicyOR` items, which it stores **in a TPM2 NV
index**. A secret is then bound to it with `TPM2_PolicyAuthorizeNV`.

Confirmed in the binary: `tpm2_policy_authorize_nv`,
`tpm2_calculate_policy_authorize_nv`, `Allocating NV index to write PCR policy
to...`, `TPM2 does not support PolicyAuthorizeNV command, refusing.`, and the
policy record at `/var/lib/systemd/pcrlock.json`.

Two things it is **not**, both worth stating because they are easy to assume:

- **It does not extend any PCR.** It only reads them. A PCR value that changed is
  not pcrlock's doing; `systemd-pcrosseparator.service` is the unit that extends
  PCRs 0–7, 9, 12–14, and it does so whether or not pcrlock exists. See
  [SYSTEMD-PCROSSEPARATOR.issue](SYSTEMD-PCROSSEPARATOR.issue).
- **It is not a value source.** Its output is a *policy* in NV, not a digest.
  Getting a digest out of it means `systemd-pcrlock predict`, which is a different
  and lesser thing than what it is for.

On this host it is present but not enrolled: no `/var/lib/pcrlock.d`, no
`/var/lib/systemd/pcrlock.json`, and `systemd-pcrlock is-supported` reports
`partial`.

---

## 2.1 What `predict` actually produces

From `systemd-pcrlock(8)`, and this decides both options:

> Predicts the PCR state on future boots… and then generate **all possible
> resulting PCR values for all combinations of component variants**. Note that **no
> prediction is made for PCRs whose value does not match the event log records, for
> which unrecognized measurements are discovered or for which components are defined
> that cannot be found in the event log.** This is a safety measure to ensure that
> any generated access policy can be fulfilled correctly on current and future boots.

Two consequences worth being blunt about.

**pcrlock does not absorb an unrecognised change — it drops the PCR.** Faced with a
measurement it cannot account for, it makes no prediction for that register. That is
the same choice tpm2-kira makes (refuse rather than guess), so adopting pcrlock would
not remove the need to intervene when the platform changes. It would relocate it:
instead of an error at seal time, the affected PCR quietly leaves the policy, and the
policy is weaker than the operator believes. `--strict=BOOL`, added in systemd 262,
exists to turn that into a failure — which is an admission that the default is a
footgun.

**The default PCR set is 0–5, 7, 11, 13–15.** PCR 9 is not in it, and neither are 8
and 12. So for the one register where tpm2-kira genuinely *must* predict — PCR 9,
whose live register is polluted after unlock — pcrlock offers nothing.

## 2. Option A — pcrlock as a PCR value source (`0p`, `7p`, …)

Run `systemd-pcrlock predict`, take the digest, put it in tpm2-kira's own
`PolicyPCR`. Fits the existing model: a source produces a value, nothing else
changes.

**Why it does not work well.**

*It throws away the point.* pcrlock's central feature is alternative variants —
bless this kernel and the next one. A `PolicyPCR` digest encodes exactly one
composite. tpm2-kira's `PolicyOR` has exactly two branches, PCR and PolicySigned,
so there is nowhere to put N alternatives without redesigning the policy and the
blob. Reduced to a single unambiguous prediction, pcrlock offers little that the
register does not already give.

*It would be a subprocess in the seal path.* The project removed a source for
close to this reason: blob format v7 retired `p:COMMAND`, which stored a command
string that `reseal` executed — arbitrary code execution as root, found by a
pentest ([pentest2/vulnerabilities/vuln-0001.md](pentest2/vulnerabilities/vuln-0001.md)).
A fixed binary path with no blob-supplied argument is a genuinely different risk
profile, so this is not the same mistake; but the UKI source was deliberately
written to parse the image in-process rather than shell out, and that preference
still holds.

*The PCR source byte matters.* Byte **2 is retired and must not be reused** — it
identified the removed predict source. A new source takes byte **4**.

*And for PCRs 0–7 there is no gap to close.* The register is already the value the
next boot presents.

**The one real gain**, and it is narrow: reseal *before* rebooting after a
firmware, shim or bootloader update. Today `11u` can do that for PCR 11 because it
reads the image on disk, but PCRs 0, 4 and 7 cannot — you reboot, get no code
once, and reseal afterwards. pcrlock's prediction could close that. Worth revisiting
if that turns out to annoy people in practice; not worth a new source, a blob
version and a subprocess before then.

---

## 3. Option B — pcrlock's NV policy as a third PolicyOR branch

Make the sealed object's `authPolicy` a `PolicyOR` over three branches:
`PolicyPCR`, `PolicySigned`, and `PolicyAuthorizeNV` against pcrlock's NV index.

This is the architecturally natural fit, and it is the one to think hardest about,
because the benefit is real: pcrlock regenerates its policy whenever a component
changes, via `systemd-pcrlock-make-policy.service`. A secret bound to it keeps
unsealing across kernel and firmware updates **with no reseal at all**. Every
churn complaint in this project — PCR 11 per kernel, PCRs 8/9 per initramfs, the
reseal-after-reboot rule on Debian — would go away.

**Why it should still not be the default, and probably not offered at all.**

*It inverts what tpm2-kira is for.* This tool exists so that an **unexpected**
change is visible before a passphrase is typed. pcrlock exists so that an
**expected** change does not break unlocking. Those goals pull opposite ways.
pcrlock blesses predicted variants ahead of time, so a secret released through
that branch shows a valid TOTP code for any blessed state — including one the user
has never seen before and has had no chance to judge.

*It adds a re-blessing path that root can walk, and that survives reboot.* The
threat model already concedes that root on a running, measured system can unseal
while the PCRs still match ([SECURITY-BACKGROUND.md](SECURITY-BACKGROUND.md) §8).
This is worse in kind: an attacker with root runs `systemd-pcrlock lock-uki` on
their own kernel and `make-policy`, and the TOTP code appears **after the reboot
into it**. Today that requires the signing key. The whole reason the PolicySigned
branch is a recovery path rather than a convenience is that holding the key is the
thing being proven.

*The NV index's write protection settles it, and not favourably.* The man page:

> The NV index contents may be changed (and thus the policy stored in it updated) by
> providing an **access PIN**. This PIN is normally **generated automatically and
> stored in encrypted form** (with an access policy binding it to the NV index
> itself) **in the aforementioned JSON policy file**.

That file is `/var/lib/systemd/pcrlock.json`, on the root filesystem — which is
unlocked and readable by root for the entire time the system is running. So the
policy is updatable by root, without any secret the operator holds. The re-blessing
path above is therefore real, not hypothetical: root reads the PIN, runs
`lock-uki` and `make-policy`, and the TOTP code appears after the reboot into the
attacker's kernel.

Contrast with tpm2-kira's own NV index, whose write policy is `PolicySigned`
against the signing key (§9), and where that key is deliberately the one thing an
attacker in the pre-unlock window cannot reach.

*It is experimental.* The man page says the interface may still change. A blob
format version and a third policy branch are expensive things to bind to that.

*It costs a blob version and a policy redesign.* `PolicyOR` is two branches today
and the blob stores one `SignedBranchDigest`; a third branch means format v10,
changes to `policy_or.go` for computing and satisfying it, and every existing user
re-sealing and re-enrolling their authenticator.

**When it would be the right answer:** if the goal changed from *tamper evidence*
to *unlock convenience* — the goal `systemd-cryptenroll --tpm2-pcrlock=` already
serves. For that goal pcrlock is better than anything here. But then tpm2-kira is
not the tool, and adding the branch would quietly convert it into a weaker version
of one that exists.

---

## 4. Recommendation

**Adopt neither option now.** Instead take the one finding from this
investigation that stands on its own.

### Read the userspace event log for the measure-point extends

pcrlock's first input is `/run/log/systemd/tpm2-measure.log` — the log of what
*systemd* measured, which the firmware log does not contain. tpm2-kira needs
exactly that information and currently gets it from a hardcoded list of two words:

```go
// measurepoint.go
os-separator   -> PCRs 0-7, 9, 12, 13, 14
enter-initrd   -> PCR 11
```

Those constants are correct today and were derived by hand, arithmetically, after
early boot measurements changed underneath the project and broke every sealed
policy — see [SYSTEMD-PCROSSEPARATOR.issue](SYSTEMD-PCROSSEPARATOR.issue) §5:

> an initramfs generator upgrade can change the set of units that run in early
> boot, and therefore change PCR values, without any of the measured components
> changing.

**Correcting an overstatement from an earlier draft of this document:** a hardcoded
list does *not* fail silently today. `DetectMeasurePointExtends` compares the
register against both the bare replay and the replay plus the known words, and when
it matches neither it **refuses to seal**, naming the PCR and telling the user to
use the register source instead. The silent version of this failure was the original
1.x behaviour, before the detection existed; that is what the incident was.

So the benefit is narrower than "prevents silent breakage", and worth stating
precisely:

- When systemd adds an early extend tpm2-kira does not know about, the `e` source
  stops working with a clear error. The register source keeps working. For PCRs 0–7
  that is a mild inconvenience, because the register is the recommended source
  anyway.
- **For PCR 9 it is not mild.** The register is unusable there (polluted after
  unlock), so `9e` is the only way to seal it, and `9e` is what the guided advisor
  suggests on any GRUB system. A systemd change would break sealing PCR 9 outright
  until tpm2-kira learned the new word.
- And pcrlock cannot cover for that, because PCR 9 is not in its default set
  (§2.1). So reading the log ourselves is the only route that keeps the one
  register requiring a prediction working across a platform change.

`tools/pcrtool.py verify` already parses this log in Python and is the reason
full-chain diagnosis works; the Go binary does not.

**Sketch.** No new source, no blob version, no subprocess.

1. `internal/kira/systemdlog.go`: parse `/run/log/systemd/tpm2-measure.log` —
   JSON-seq records carrying `pcr`, `digest` and the measured word.
2. `DetectMeasurePointExtends` gains a third answer besides *extends present* and
   *extends absent*: **extends read from the log**, listing what was actually
   measured before `cryptsetup-pre.target` rather than assuming.
3. Keep the two constants as the fallback for when the log is unreadable — it lives
   in `/run`, so it is absent when sealing from a rescue system.
4. Record in the blob what was applied. `MeasurePointExtends` is already a free-form
   `"word:pcr,pcr;word:pcr"` string in the signed payload, so richer content needs
   **no format change** — the field was designed for this.
5. The guided advisor reports the source of the extends, so "read from the systemd
   log" versus "assumed from built-in constants" is visible rather than implied.

That closes the failure mode that has actually bitten this project, costs no
compatibility, and needs pcrlock installed on precisely nobody's machine.

### If you want pcrlock support anyway

Order matters. Do Option A's narrow case first — `predict` as a way to reseal
before rebooting after a firmware or bootloader update — as an explicit flag on
`reseal`, not a PCR source:

```
tpm2-kira reseal --predict-next-boot
```

It reuses the existing `PolicyPCR`, needs no blob change and no new source byte,
and either produces a value or says it could not. If that proves useful, a `p`
source (byte 4) becomes an easy follow-on. Option B should wait for pcrlock to
stop being experimental, and for the NV index write protection in §3 to be
answered — and even then it deserves its own discussion about what tpm2-kira is
promising, not just a flag.

---

## 5. Open questions

| # | Question | How to answer |
|---|---|---|
| 1 | ~~Is pcrlock's NV index writable under owner auth?~~ | **Answered** (§3): updatable with an access PIN that is stored in `/var/lib/systemd/pcrlock.json` on the root filesystem, so root can rewrite the policy |
| 2 | Does `systemd-pcrlock predict` emit per-PCR digests usable as single values? | **Partly answered** (§2.1): it emits *all* variant combinations, so a single value only exists where one variant is defined. Confirm the JSON shape with `sudo systemd-pcrlock predict --json=pretty` on an enrolled host |
| 3 | What exactly does `is-supported` reporting `partial` exclude? | `systemd-pcrlock is-supported --json=pretty` |
| 4 | Is the userspace log format stable enough to parse? | Compare `/run/log/systemd/tpm2-measure.log` across systemd versions; `tools/pcrtool.py` already parses one shape |

Questions 1 and 2 are answered from the man page. Question 3 and the JSON shape in
2 still need an enrolled host, and enrolling pcrlock allocates a TPM NV index and
writes a policy — not something to do to a system uninvited.
