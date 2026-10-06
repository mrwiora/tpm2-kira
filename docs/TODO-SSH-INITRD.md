# TODO — Unlocking over SSH in the initrd

Status: idea, noted 2026-10-06. Not implemented. The local console case
comes first (`tpm2-kira run`: fresh code every 30 s, Enter releases the boot,
90 s hold by default).

## The problem

`tpm2-kira.service` holds READY back while it shows codes; the OS separator
runs after READY and makes the key's policy unsatisfiable until the next
boot. A remote admin who logs into the initrd over SSH after that gets no
fresh code: `tpm2-kira reveal` reports the slot as locked. Today's setup
(mkinitcpio-systemd-tool, tinysshd) runs

    SD_TINYSSH_COMMAND="tpm2-kira && systemd-tty-ask-password-agent --query --watch"

which assumes a code can be computed whenever the admin arrives.

## The idea

tpm2-kira starts the SSH server in the initrd itself, during the hold, so it
controls the whole unlock conversation: the admin logs in, sees the fresh
code (the hold's display, or `reveal`, both still work before READY), confirms
it, and that confirmation is the release — the same role Enter has on the
console — after which the passphrase prompt appears and is answered through
`systemd-tty-ask-password-agent`. Nothing is served after the release.

Open points: the hold length for remote use (the default 90 s is for a person
at the keyboard; a remote unlock needs minutes, or a hold without timeout
that an operator releases), the SSH server's own ordering in the initrd (it
must not wait for `sysinit.target`, which waits for the separator), and
whether the release should also be offered to the Bluetooth gate
(`tpm2-kira-attest.service`) and the planned network attestation: a verdict
from the phone or the server could release the boot the same way.
