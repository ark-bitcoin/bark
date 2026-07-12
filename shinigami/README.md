# Bark / Cairo manifest-binding interoperability

This workspace crate exports deterministic inputs for version 1 of the
experimental `ArkTaprootMiniscriptClaim` Cairo ABI. It does not execute
Bitcoin Script, invoke Shinigami, generate a STARK proof, or verify one.

`ManifestBindingClaim::from_pubkey_vtxo_owner_exit` is the Bark-specific entry
point. It accepts a pubkey-policy VTXO and derives its amount, exit delay,
BIP341 TapLeaf hash, Merkle root, and control-block path. The caller must
validate the VTXO first; `Vtxo<Full>` only indicates that its fields are
present.

The settlement commitment remains external because Bark does not define one
for this prototype. Cooperative Bark spends use the Taproot key path and are
therefore not represented as a script-leaf claim. HTLC VTXOs are rejected
because they do not have the simple owner-CSV shape assigned to ABI role 2.

The encoder is pinned to the LF-normalized Cairo source SHA-256
`ab422d117be16af2a2754a838769b4fa19b97f694af88309a82233669f59c472`.
The executable accepts the following positional JSON fields:

| Index | Field |
| ---: | --- |
| 0-1 | manifest id, big-endian `u128` limbs |
| 2-3 | Taproot root, big-endian `u128` limbs |
| 4-5 | selected leaf hash, big-endian `u128` limbs |
| 6 | external leaf-role code |
| 7-8 | path commitment, big-endian `u128` limbs |
| 9 | Cairo path fold |
| 10 | active sibling count |
| 11-19 | three fixed sibling slots: high limb, low limb, side |
| 20-21 | settlement hash, big-endian `u128` limbs |
| 22 | amount in satoshis (`u64`) |
| 23 | exit delay (`u32`) |
| 24 | Cairo binding commitment |

Sibling side `0` means right and `1` means left. Unused sibling slots are
zero-filled. Every value is emitted as a quoted, lowercase, minimally padded
`0x` string in the exact array format consumed by the external prover script.

The Cairo mixer is linear and non-cryptographic. A successful proof of this
predicate is not proof that a Bitcoin transaction, signature, Taproot spend,
or Bark protocol transition is valid. Consumers must pin the expected Cairo
program and public statement independently and must never use this output as
spend authorization.

## Bark-derived commitments

The Bark constructor uses untagged SHA-256 with these exact byte preimages:

- `manifest_id = SHA256("bark/ark-taproot-miniscript-claim/v1/manifest" ||
  ProtocolEncoding(vtxo))`;
- `path_commitment = SHA256("bark/ark-taproot-miniscript-claim/v1/path" ||
  taproot_root[32] || selected_leaf_hash[32] || depth_u8 ||
  (side_u8 || sibling_hash[32])*)`.

Path siblings are encoded leaf-to-root; side `0` means right and side `1`
means left. There are no length prefixes or separators beyond the one-byte
depth and side fields. The Bark-derived golden vector locks these conventions,
including the current `ProtocolEncoding` representation.
