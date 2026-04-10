# BIP-XXXX: PQC Precommitment for Post-Quantum Migration

```
BIP: XXXX
Layer: Applications (future consensus)
Title: PQC Precommitment for Post-Quantum Migration
Author: Daniel Buchner <danjbuchner@gmail.com>
Status: Draft
Type: Informational
Created: 2026-04-10
License: BSD-3-Clause
```

## Abstract

This document describes a precommitment construction for Bitcoin script-path spending using existing tapscript semantics from BIP 342.

The construction uses:

- one mandatory secp256k1 Schnorr signature slot, and
- one or more additional slots encoded as unknown tapscript public key types that commit to future post-quantum verification keys.

Under current consensus, these future-PQC slots are satisfied using non-empty dummy witness elements of the lengths defined below. In a future soft fork, the same slot encodings may be assigned real `SLH-DSA (SPHINCS+)`, `SHRINCS`, or other explicitly defined verification semantics while preserving the original output and script.

This document does not specify that future soft fork. It only specifies the current commitment pattern and the assumptions under which such an activation could later occur.

> NOTE: the author could have missed something that invalidates this idea, so be kind if he turns out to be retarded.

## Scope And Assumptions

This construction is intentionally narrow and depends on the following assumptions:

- Long-range quantum exposure of Taproot output keys is handled outside this document by `P2MR` or an equivalent mechanism. `P2MR`, proposed in [BIP 360](https://bips.xyz/360), is a Taproot-like output construction that commits to a Merkle root while omitting Taproot's key-path spend.
- This document specifies candidate slot-key encodings for `SLH-DSA (SPHINCS+)` and `SHRINCS`. `ML-DSA`, `NTRU Prime`, and other larger key formats are out of scope.
- Pre-activation spends use non-empty dummy witness elements for the future-PQC slots, with lengths chosen as specified in [Dummy Witness Encoding](#dummy-witness-encoding).
- Post-activation, full future-PQC signature material is validated from the annex or another future-defined witness location, rather than from oversized current tapscript stack elements.

Without these assumptions, the construction is not a complete post-quantum migration scheme.

## Motivation

### Forward Commitment Without Immediate Key Migration

A useful intermediate property is the ability to create outputs today that already commit to a future post-quantum authorization structure, even if Bitcoin does not yet define that structure's validation rules.

BIP 342 provides one such hook:

- any non-zero-length public key whose length is not 32 bytes is an unknown tapscript public key type, and
- signature validation for unknown public key types is currently treated as successful when the provided signature element is non-empty.

This allows a script to commit today to future validation slots that can later become stricter under soft-forked rules.

### Candidate Slot-Key Families

This document currently defines two future-PQC slot-key families that fit the unknown-key construction used here.

`SLH-DSA (SPHINCS+)`

- `SLH-DSA-SHA2-128s`: 32-byte raw public key, 7856-byte signature
- `SLH-DSA-SHA2-192s`: 48-byte raw public key, 16224-byte signature
- `SLH-DSA-SHA2-256s`: 64-byte raw public key, 29792-byte signature

These are the standardized small-signature SHA2 parameter sets. They provide distinct NIST security categories while keeping the currently revealed public keys as small as possible. The corresponding `f` variants are not included because they do not improve current on-chain fit and would only increase the future signature transport burden.

`SHRINCS`

- `SHRINCS-L1`: 16-byte outer public key, 324-byte stateful-path signature for `q = 1`
- `SHRINCS-L3`: 24-byte outer public key, 660-byte stateful-path signature for `q = 1`
- `SHRINCS-L5`: 32-byte outer public key, with a correspondingly larger stateful-path signature under the same construction

These are candidate `SHRINCS` tags based on the compact outer public-key form described in the Delving Bitcoin proposal. They fit the same unknown-key precommitment pattern used here. As with the `SLH-DSA (SPHINCS+)` entries above, exact future verification semantics remain out of scope for this document.

For all of the families above, future activation must obtain the actual signature material from somewhere other than the current `sig` operand position.

## Definitions

- Known key type: A 32-byte x-only public key interpreted as BIP 340 secp256k1 in tapscript.
- Unknown key type: Any non-zero-length public key whose length is not 32 bytes.
- Dummy slot witness: A non-empty witness element used today to satisfy an unknown key type.
- `SLH-DSA (SPHINCS+)` slot key: A tagged `SLH-DSA (SPHINCS+)` public key encoded so that it is an unknown tapscript public key type today.
- `SHRINCS` slot key: A tagged `SHRINCS` outer public key encoded so that it is an unknown tapscript public key type today.
- Activation: A future soft fork that assigns real future-PQC verification semantics to the slot-key encodings defined here.

## Slot-Key Encodings

The following byte prefixes are candidate tags for this construction. They are chosen to avoid conflict with draft BIP 118's `0x01` prefix convention.

All slot-key encodings defined in this section are constructed so that they are:

- non-zero length,
- not 32 bytes, and therefore
- unknown tapscript public key types under current BIP 342 rules.

All of the resulting pushed elements also fit current consensus limits.

### `SLH-DSA (SPHINCS+)` Slot Keys

```text
slh-dsa-slot-key = slh-dsa-tag slh-dsa-pubkey

slh-dsa-tag    = %x10 / %x11 / %x12
%x10           = SLH-DSA-SHA2-128s
%x11           = SLH-DSA-SHA2-192s
%x12           = SLH-DSA-SHA2-256s

slh-dsa-pubkey = 32OCTET / 48OCTET / 64OCTET
```

Resulting `SLH-DSA (SPHINCS+)` slot-key sizes are:

- `0x10 || pk128`: 33 bytes
- `0x11 || pk192`: 49 bytes
- `0x12 || pk256`: 65 bytes

### `SHRINCS` Slot Keys

The `SHRINCS` tag values below follow the candidate outer-key sizes described in the Delving Bitcoin proposal.

For compatibility with the current precommitment pattern, an implementation can use a one-byte tag followed by the compact outer `SHRINCS` public key. The Delving Bitcoin proposal describes 16-byte outer keys at NIST level 1 and 24-byte outer keys at level 3; the 32-byte outer-key case shown below is a natural level-5 analogue and still needs a tag byte so the resulting pushed element is not interpreted as a 32-byte BIP 340 key.

```text
shrincs-slot-key = shrincs-tag shrincs-pubkey

shrincs-tag    = %x20 / %x21 / %x22
%x20           = SHRINCS-L1
%x21           = SHRINCS-L3
%x22           = SHRINCS-L5

shrincs-pubkey = 16OCTET / 24OCTET / 32OCTET
```

Resulting `SHRINCS` slot-key sizes are:

- `0x20 || pk_shr_l1`: 17 bytes
- `0x21 || pk_shr_l3`: 25 bytes
- `0x22 || pk_shr_l5`: 33 bytes

## Dummy Witness Encoding

Current tapscript consensus treats an unknown public key type as successful only when the provided signature element is non-empty.

Accordingly, pre-activation slot witnesses MUST be non-empty.

To satisfy the BIP 342 per-script sigops budget without adding unnecessary weight, each slot witness SHOULD be the minimum non-empty size that makes its slot self-fund the 50-byte sigops decrement once the script is revealed.

For the slot-key encodings defined here, the canonical dummy witnesses are:

- `%x10` (`SLH-DSA-SHA2-128s`, 33-byte slot key): 14-byte dummy witness
- `%x11` (`SLH-DSA-SHA2-192s`, 49-byte slot key): 1-byte dummy witness
- `%x12` (`SLH-DSA-SHA2-256s`, 65-byte slot key): 1-byte dummy witness
- `%x20` (`SHRINCS-L1`, 17-byte slot key): 30-byte dummy witness
- `%x21` (`SHRINCS-L3`, 25-byte slot key): 22-byte dummy witness
- `%x22` (`SHRINCS-L5`, 33-byte slot key): 14-byte dummy witness

A canonical encoding is all-zero bytes of the required length:

```text
dummy128 = 14 * %x00
dummy192 = 1  * %x00
dummy256 = 1  * %x00
dummy-shr-l1 = 30 * %x00
dummy-shr-l3 = 22 * %x00
dummy-shr-l5 = 14 * %x00
```

Rationale:

- each executed signature opcode with a non-empty signature consumes 50 sigops-budget units,
- the first real Schnorr signature is covered by tapscript's free 50-unit allowance,
- each additional slot should therefore contribute at least 50 bytes to the serialized witness,
- a slot contributes `len(dummy) + len(slot-key) + 3` witness bytes in this construction.

Thus `len(dummy) >= 47 - len(slot-key)`, which yields:

- `30` for a 17-byte slot key,
- `22` for a 25-byte slot key,
- `14` for a 33-byte slot key,
- `0` for a 49-byte slot key, rounded up to `1` because the witness must be non-empty,
- `-18` for a 65-byte slot key, also rounded up to `1` because the witness must be non-empty.

Implementations that prefer a uniform encoding MAY use the 30-byte dummy for all defined slot types.

## Script Construction

A canonical tapscript pattern is:

```text
<pk_ecc> OP_CHECKSIGVERIFY

0
<pk_pq_1> OP_CHECKSIGADD
<pk_pq_2> OP_CHECKSIGADD
...
<pk_pq_n> OP_CHECKSIGADD

<m> OP_NUMEQUAL
```

with witness stack:

```text
<w_n> ... <w_2> <w_1> <sig_ecc>
```

where:

- `<pk_ecc>` is a 32-byte x-only secp256k1 public key,
- each `<pk_pq_i>` is either an `SLH-DSA (SPHINCS+)` slot key or a `SHRINCS` slot key as defined above,
- each `<w_i>` is currently a non-empty dummy slot witness of the tag-appropriate length defined above,
- `<sig_ecc>` is a valid BIP 340 Schnorr signature for `<pk_ecc>`.

If all future-PQC slots are intended to become mandatory after activation, set `m = n`.

## Behavior Under Current Consensus

Under current BIP 342 rules:

- `<pk_ecc>` is a known key type, so `OP_CHECKSIGVERIFY` enforces a valid Schnorr signature.
- Each `<pk_pq_i>` is an unknown key type, so no actual signature verification is performed today.
- Each non-empty `<w_i>` is treated as a successful signature for `OP_CHECKSIGADD`, incrementing the accumulator by 1.

Therefore, when `m = n`, the script presently enforces:

- one real secp256k1 Schnorr signature, and
- `n` non-empty placeholder witnesses for the future-PQC slots.

An empty `<w_i>` does not increment the accumulator and therefore does not satisfy a mandatory slot.

## Future Activation Model

This construction assumes a future soft fork may define the slot-key tags above as real future-PQC public key types.

That activation should not rely on enlarging the current tapscript stack-element limit for existing leaf-version `0xc0` scripts. Instead, it should validate the full future-PQC signature material from the annex or another future-defined witness location that is not the existing `sig` operand consumed by `OP_CHECKSIGADD`.

Under this model:

- the slot key revealed today remains unchanged,
- the small witness element consumed by `OP_CHECKSIGADD` may remain a compact non-empty selector or handle,
- the full future-PQC signature bytes are supplied elsewhere by the future upgrade,
- the existing output and script do not need to be rewritten.

For any future-PQC tag included in the precommitment set, a later soft fork would need to define:

- the exact public-key form committed in script,
- the exact signature encoding and where that signature material is transported,
- and the verification rules applied to that tag.

Different key families may require different verification details, but those scheme-specific rules are out of scope for this document.

This document intentionally leaves the exact post-activation wire format unspecified.

## Security Model

This construction only claims the following:

- Today, the script path commits to a future-PQC authorization structure while remaining spendable with dummy slot witnesses.
- After activation, the same script path can require real `SLH-DSA (SPHINCS+)`, `SHRINCS`, or other explicitly defined authorization for those slots.

This document does not claim, by itself, to solve Taproot's exposed-output-key problem. It assumes that problem is handled separately by `P2MR` or an equivalent mechanism.

Without that external assumption, Taproot key-path exposure remains a blocker for any "park today, survive Q-Day later" claim.

## Operational Notes

### Relay Policy

Although this construction is consensus-valid today, Bitcoin Core's default relay policy treats executed unknown tapscript public key types as non-standard.

That is a policy issue, not a consensus issue.

### Why Key-Path Disable Is Not Assumed Here

Other proposals address long-exposure quantum risk by removing Taproot key-path spends entirely, most notably `P2MR` in [BIP 360](https://bips.xyz/360).

This document does not rely on that approach; it assumes long-exposure key-path risk is handled separately if needed.

## Risks And Limitations

- The construction depends on a future soft fork to assign real semantics to the slot-key encodings.
- It depends on a future design for annex-based or otherwise relocated future-PQC signature transport.
- The exact future verification semantics for each included key family remain out of scope for this document.
- It does not, on its own, address long-range Taproot output-key exposure.

## Conclusion

Under the assumptions stated above, unknown tapscript public key types can be used today as forward-compatibility slots for future post-quantum authorization.

The resulting pattern allows for a future-compatible PQC activation:

- raw `SLH-DSA (SPHINCS+)` public keys fit today when tagged as unknown key types,
- compact outer `SHRINCS` public keys can also fit today when tagged as unknown key types,
- current spends can use non-empty dummy slot witnesses sized to satisfy the tapscript sigops budget,
- future activation can define real `SLH-DSA (SPHINCS+)` or `SHRINCS` validation using annex-backed or otherwise relocated signature material.
