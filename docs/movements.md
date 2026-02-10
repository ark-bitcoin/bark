# Movement System Documentation

The movement system tracks all balance and VTXO changes within bark. Each movement represents a distinct action that
the wallet performs.

## Table of Contents

- [Quick Reference](#quick-reference)
- [Movement Schema](#movement-schema)
  - [Core Fields](#core-fields)
  - [MovementDestination](#movementdestination)
  - [PaymentMethod](#paymentmethod)
- [Subsystems and Movement Kinds](#subsystems-and-movement-kinds)
- [Movement Subsystems](#movement-subsystems)
  - [1. bark.arkoor](#1-barkarkoor)
  - [2. bark.board](#2-barkboard)
  - [3. bark.offboard](#3-barkoffboard)
  - [4. bark.lightning_send](#4-barklightning_send)
  - [5. bark.lightning_receive](#5-barklightning_receive)
  - [6. bark.round](#6-barkround)
  - [7. bark.exit](#7-barkexit)
- [FAQ](#faq)

## Quick Reference

**Identifying Movement Types:**
- Check `subsystem.name` and `subsystem.kind` to determine the operation type
- Example: `{"name": "bark.arkoor", "kind": "send"}` = Offchain ark payment

**Common Tasks:**
- **Calculate balance change**: Use `effective_balance_sat` (includes all offchain fees)
- **Find fee costs**: Check `offchain_fee_sat` for ark and lightning fees, `metadata.onchain_fee_sat` for Bitcoin network fees
- **Check completion**: Movement is complete when `status` != `pending` and `time.completed_at` is not null
- **Identify VTXOs**: `input_vtxos` = consumed, `output_vtxos` = created, `exited_vtxos` = marked for emergency exit

**Status Interpretation:**
- `"pending"` → In progress, VTXOs may be locked
- `"successful"` → Completed successfully, check `effective_balance_sat` for actual change
- `"failed"` → Operation failed, but VTXOs may still have changed (check `output_vtxos`)
- `"canceled"` → Canceled by protocol or user

**Balance Semantics:**
- Negative values = outgoing (sending/exiting)
- Positive values = incoming (receiving/boarding)
- `effective_balance_sat` = actual change (most accurate)
- `intended_balance_sat` = expected change (may exclude fees)

## Movement Schema

All movements share a common schema with the following fields:

### Core Fields

| Field                   | Type           | Description                                                                                  |
|-------------------------|----------------|----------------------------------------------------------------------------------------------|
| `id`                    | `number`       | Internal ID of the movement                                                                  |
| `status`                | `string`       | Status: `"pending"`, `"successful"`, `"failed"`, or `"canceled"`                             |
| `subsystem`             | `object`       | `{name: string, kind: string}` - Identifies the subsystem and operation type                 |
| `intended_balance_sat`  | `number` (i64) | The intended balance change in sats (negative for outgoing, positive for incoming)           |
| `effective_balance_sat` | `number` (i64) | The actual balance change in sats after fees and other considerations                        |
| `offchain_fee_sat`      | `number` (u64) | Offchain/ark fees paid for the current transaction in sats                                   |
| `sent_to`               | `array`        | Array of `MovementDestination` objects - payment methods/addresses where funds were sent     |
| `received_on`           | `array`        | Array of `MovementDestination` objects - payment methods/addresses where funds were received |
| `input_vtxos`           | `array`        | Array of VTXO IDs consumed by this movement                                                  |
| `output_vtxos`          | `array`        | Array of VTXO IDs created by this movement                                                   |
| `exited_vtxos`          | `array`        | Array of VTXO IDs that have been marked for exit                                             |
| `time`                  | `object`       | `{created_at, updated_at, completed_at?}` - Timestamp information (ISO 8601 format)          |
| `metadata`              | `object?`      | Optional subsystem-specific metadata (see subsystem details below)                           |

### MovementDestination

```json
{
  "destination": <PaymentMethod>,
  "amount_sat": <number>
}
```

### PaymentMethod

Tagged union with `type` and `value` fields:

```json
{"type": "ark", "value": "<ark_address>"}
{"type": "bitcoin", "value": "<btc_address>"}
{"type": "output-script", "value": "<hex_script>"}
{"type": "invoice", "value": "<bolt11_or_bolt12_invoice>"}
{"type": "offer", "value": "<bolt12_offer>"}
{"type": "lightning-address", "value": "<email@domain.com>"}
{"type": "custom", "value": "<custom_string>"}
```

## Subsystems and Movement Kinds

The following table lists all available subsystems and their associated movement kinds:

| Subsystem Name           | Movement Kind(s)                            | Description                                                      |
|--------------------------|---------------------------------------------|------------------------------------------------------------------|
| `bark.arkoor`            | `"send"`, `"receive"`                       | Offchain transfers between ark users                             |
| `bark.board`             | `"board"`                                   | Moving funds from onchain to ark                                 |
| `bark.offboard`             | `"offboard"`, `"send_onchain"`                                   | Moving funds from ark to onchain                                 |
| `bark.exit`              | `"start"`                                   | Initiation of emergency exits, redeeming offchain funds onchain |
| `bark.lightning_send`    | `"send"`                                    | Sending funds via the Lightning Network                          |
| `bark.lightning_receive` | `"receive"`                                 | Receiving funds via the Lightning Network                        |
| `bark.round`             | `"refresh"` | Various different round participation methods                    |

## Movement Subsystems

> **Note:** In the examples below, JSON objects include inline comments (using `//`) to explain field meanings.
> Standard JSON does not support comments - these are included for documentation purposes only.

### 1. bark.arkoor

Offchain transfers between ark users.

#### Kind: `"send"`
Sending funds to another ark address offchain.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.arkoor",
    "kind": "send"
  },
  "intended_balance_sat": -10000,
  "effective_balance_sat": -10100,
  "offchain_fee_sat": 100,
  "sent_to": [
    {
      "destination": {
        "type": "ark",
        "value": "ark1pm6..."
      },
      "amount_sat": 10000
    }
  ],
  "input_vtxos": ["a1b2c3d4...:0", "e5f6a7b8...:1"],
  "output_vtxos": ["c9d0e1f2...:0"]
}
```

#### Kind: `"receive"`
Receiving funds from another ark user offchain.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.arkoor",
    "kind": "receive"
  },
  "intended_balance_sat": 10000,
  "effective_balance_sat": 10000,
  "offchain_fee_sat": 0,
  "received_on": [
    {
      "destination": {
        "type": "ark",
        "value": "ark1pm6..."
      },
      "amount_sat": 10000
    }
  ],
  "output_vtxos": ["f3a4b5c6...:0", "d7e8f9a0...:0", "b1c2d3e4...:0"]
}
```

**Notes:**
- The `received_on` field contains the Ark address(es) the VTXOs were received on, aggregated by address with the total
  amount received on each.

---

### 2. bark.board

Moving funds from onchain to ark.

#### Kind: `"board"`
Boarding funds onto the ark.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.board",
    "kind": "board"
  },
  "intended_balance_sat": 10000,
  "effective_balance_sat": 10000,
  "offchain_fee_sat": 0,
  "output_vtxos": ["e5f6a7b8...:0"],
  "metadata": {
    "onchain_fee_sat": 772, // Bitcoin network fees paid in sats
    "chain_anchor": "a1b2c3d4...:0"  // Blockchain anchor for the VTXO
  }
}
```

---

### 3. bark.offboard

Moving funds from ark to onchain.

#### Kind: `"offboard"`
Offboarding funds from the ark.

**Example:**
```json
{
    "status": "successful",
    "subsystem": {
      "name": "bark.offboard",
      "kind": "offboard"
    },
    "metadata": {
      "offboard_tx": "02000000...",
      "offboard_txid": "bda355fa..."
    },
    "intended_balance_sat": -10000,
    "effective_balance_sat": -10000,
    "offchain_fee_sat": 488,
    "sent_to": [
      {
        "destination": {
          "type": "bitcoin",
          "value": "tb1qf7wn..."
        },
        "amount_sat": 9512
      }
    ],
    "received_on": [],
    "input_vtxos": ["500ed65d...:0"],
    "output_vtxos": [],
    "exited_vtxos": []
}
```

#### Kind: `"send_onchain"`

Sending money to an on-chain address.

**Example:**
```json
{
    "status": "successful",
    "subsystem": {
      "name": "bark.offboard",
      "kind": "send_onchain"
    },
    "metadata": {
      "offboard_tx": "02000000...",
      "offboard_txid": "bda355fa..."
    },
    "intended_balance_sat": -10000,
    "effective_balance_sat": -10488,
    "offchain_fee_sat": 488,
    "sent_to": [
      {
        "destination": {
          "type": "bitcoin",
          "value": "tb1qf7wn..."
        },
        "amount_sat": 10000
      }
    ],
    "received_on": [],
    "input_vtxos": ["500ed65d...:0"],
    "output_vtxos": ["169c14b1...:1"],
    "exited_vtxos": []
}
```

---

### 4. bark.lightning_send

Sending funds via the Lightning Network

#### Kind: `"send"`
Sending a lightning payment using a supported method such as a BOLT11 invoice, a BOLT12 offer or a lightning address.

**Example (Invoice):**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.lightning_send",
    "kind": "send"
  },
  "intended_balance_sat": -10000,
  "effective_balance_sat": -10000,
  "offchain_fee_sat": 0,
  "sent_to": [
    {
      "destination": {
        "type": "invoice",
        "value": "lntbs100u1pj9x4vxpp5..."
      },
      "amount_sat": 10000
    }
  ],
  "input_vtxos": ["d9e0f1a2...:0"], // Array of VTXO IDs used to make the payment
  "output_vtxos": ["b3c4d5e6...:0"], // Array of change VTXO IDs from the payment and new VTXOs upon payment failure
  "exited_vtxos": [], // Array of VTXO IDs marked for exit if required, these are always HTLC VTXOs
  "metadata": {
    "payment_hash": "e3b0c442...",
    "htlc_vtxos": ["f7a8b9c0...:0"],
    "payment_preimage": "f50b3e22..."
  }
}
```

**Example (Offer):**

Same as invoice, except `sent_to` uses the offer type:
```json
  "sent_to": [
    {
      "destination": {
        "type": "offer",
        "value": "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrc2q..."
      },
      "amount_sat": 10000
    }
  ]
```

**Example (Lightning Address):**

Same as invoice, except `sent_to` uses the lightning address type:
```json
  "sent_to": [
    {
      "destination": {
        "type": "lightning-address",
        "value": "example@second.tech"
      },
      "amount_sat": 10000
    }
  ]
```

**Notes:**
- The payment process is: provide VTXOs to the server for the payment → receive HTLC VTXOs → await preimage → Swap HTLC
  VTXOs for standard pubkey VTXOs.
  - The movement is not successful until the HTLC VTXOs have been swapped/revoked.
  - If the payment fails, then the movement will still contain new VTXOs once the HTLC VTXOs have been revoked.
  - If HTLC VTXOs cannot be swapped/revoked, and they're near expiry, they'll be immediately marked for exit and a new
    exit movement will be created.
  - HTLC VTXOs are tracked separately in metadata and not in output_vtxos.
- Each payment to an offer generates a unique `payment_hash`.
- Each payment to a lightning address generates a unique `payment_hash`.
- A movement will contain a `payment_preimage` in its metadata if and only if it is successful.
- A movement will not be created until a HTLC VTXO is received from the server.

---

### 5. bark.lightning_receive

Receiving funds via the Lightning Network

#### Kind: `"receive"`
Receiving a lightning payment via a BOLT11 invoice.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.lightning_receive",
    "kind": "receive"
  },
  "intended_balance_sat": 10000,
  "effective_balance_sat": 10000,
  "offchain_fee_sat": 0,
  "received_on": [
    {
      "destination": {
        "type": "invoice",
        "value": "lntbs100u1pj9x4vxpp5..."
      },
      "amount_sat": 10000
    }
  ],
  "output_vtxos": ["e1f2a3b4...:0"],
  "exited_vtxos": [], // Array of VTXO IDs marked for exit if required, these are always HTLC VTXOs
  "metadata": {
    "payment_hash": "a7ffc6f8...",
    "htlc_vtxos": ["c5d6e7f8...:0"],
    "payment_preimage": "84f27d91..."
  }
}
```
 
**Notes:**
- The receive process is: receive HTLC VTXOs → reveal preimage → Swap HTLC VTXOs for standard pubkey VTXOs.
  - The movement is not successful until the HTLC VTXOs have been swapped/revoked.
  - If HTLC VTXOs cannot be swapped/revoked, and they're near expiry, and the preimage has been revealed, they'll be
    immediately marked for exit and a new exit movement will be created.
  - If HTLC VTXOs cannot be swapped/revoked, and they're near expiry, but no preimage has been revealed, the movement
    will be marked as canceled.
  - HTLC VTXOs are tracked separately in metadata and not in output_vtxos.
- A movement will not be created until a HTLC VTXO is received from the server.

---

### 6. bark.round

Various different round participation methods.

#### Kind: `"offboard"`
Offboarding entire VTXOs to an onchain bitcoin address.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.round",
    "kind": "offboard"
  },
  "intended_balance_sat": -8900,
  "effective_balance_sat": -10000,
  "offchain_fee_sat": 1100,
  "sent_to": [
    {
      "destination": {
        "type": "bitcoin",
        "value": "bc1qxy2k..."
      },
      "amount_sat": 8900
    }
  ],
  "input_vtxos": ["a9b0c1d2...:0"],
  "metadata": {
    "funding_txid": "b1c2d3e4..." // The funding transaction ID of the round this movement participated in
  }
}
```

#### Kind: `"refresh"`
Consolidates and refreshes the lifetime of VTXOs.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.round",
    "kind": "refresh"
  },
  "intended_balance_sat": 0,
  "effective_balance_sat": -1000,
  "offchain_fee_sat": 1000,
  "input_vtxos": ["e3f4a5b6...:0", "c7d8e9f0...:1", "a1b2c3d4...:2"],
  "output_vtxos": ["e5f6a7b8...:0"],
  "metadata": {
    "funding_txid": "c3d4e5f6..." // The funding transaction ID of the round this movement participated in
  }
}
```

#### Kind: `"send_onchain"`
Unlike `offboard` (which sends entire VTXOs), `send_onchain` sends a specific amount and returns change VTXOs if
applicable.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.round",
    "kind": "send_onchain"
  },
  "intended_balance_sat": -10000,
  "effective_balance_sat": -11000,
  "offchain_fee_sat": 1100,
  "sent_to": [
    {
      "destination": {
        "type": "bitcoin",
        "value": "bc1qar0s..."
      },
      "amount_sat": 10000
    },
    {
      "destination": {
        "type": "output-script",
        "value": "6a0b68656c6c6f20776f726c64" // Example: OP_RETURN "hello world"
      },
      "amount_sat": 0
    }
  ],
  "input_vtxos": ["d5e6f7a8...:0"],
  "output_vtxos": ["a9b0c1d2...:0"],
  "metadata": {
    "funding_txid": "f3a4b5c6..." // The funding transaction ID of the round this movement participated in
  }
}
```

**Notes:**
- Fees required to broadcast the UTXO onchain are included in the `offchain_fee_sat` field.

---

### 7. bark.exit

Initiation of emergency exits, redeeming offchain funds onchain.

#### Kind: `"start"`
A emergency exit which has been initiated.

**Example:**
```json
{
  "status": "successful",
  "subsystem": {
    "name": "bark.exit",
    "kind": "start"
  },
  "intended_balance_sat": -10000,
  "effective_balance_sat": -10000,
  "offchain_fee_sat": 0,
  "sent_to": [
    {
      "destination": {
        "type": "bitcoin",
        "value": "bc1p5cyxn..."
      },
      "amount_sat": 10000
    }
  ],
  "input_vtxos": ["f5a6b7c8...:0"]
}
```

**Notes:**
- The exit address is the taproot exit script address, a transaction for this address will only appear onchain once the
  exit is completed.
- The status of an exit will be `"successful"` the moment a VTXO is marked for exit, not when the exit process is
  completed since movements only track offchain funds. You can query ongoing exits for further details about an exit.

---

## FAQ

### When is a movement considered complete?

A movement is complete when the `time.completed_at` field is not null and the `status` is `"successful"`, `"failed"`,
or `"canceled"`. A completed movement may still have resulted in VTXO changes even if it failed.

### Why is `effective_balance_sat` different from `intended_balance_sat`?

- `intended_balance_sat` represents the expected balance change provided the movement succeeds, excluding fees.
- `effective_balance_sat` represents the actual balance change, including all offchain fees.
- For example, sending 10,000 sats with a 100 sat fee: `intended_balance_sat = -10000`, `effective_balance_sat = -10100`

Always use `effective_balance_sat` for accurate balance calculations.

### What happens to VTXOs in a failed movement?

Even when a movement fails (`status == "failed"`), VTXOs can still change. The movement will show:
- `input_vtxos`: VTXOs that were consumed
- `output_vtxos`: New VTXOs created (e.g., change VTXOs, revocation VTXOs for failed lightning payments)
- `effective_balance_sat`: Might be 0 or reflect partial changes if a payment doesn't work.

This is common in lightning payments where HTLC VTXOs need to be revoked after a payment fails.

### What are HTLC VTXOs and why aren't they in `output_vtxos`?

HTLC (Hash Time-Locked Contract) VTXOs are intermediate states used during Lightning Network payments. They are:
- Tracked separately in `metadata.htlc_vtxos` as an array of VTXO IDs
- Not included in `output_vtxos` because they're temporary/locked
- Eventually swapped for standard VTXOs (success) or revoked (failure)
- May be marked for exit in `exited_vtxos` if they can't be swapped and are near expiry

### What's the difference between `offboard` and `send_onchain`?

**`offboard`** (bark.round):
- Sends entire VTXO(s) onchain
- No change VTXOs created
- Example: Offboard a 10,000 sat VTXO → receive ~8,900 sats onchain (after fees)

**`send_onchain`** (bark.round):
- Sends a specific amount onchain
- Creates change VTXOs if input is larger than amount
- Example: Send 5,000 sats from a 10,000 sat VTXO → receive 5,000 sats onchain + ~3,900 sat change VTXO

### Can a successful movement have an empty `sent_to` array?

Yes! Movements like:
- `bark.arkoor` receive (you're receiving, not sending)
- `bark.board` board (moving funds from onchain to ark)
- `bark.round` refresh (consolidating/refreshing VTXOs)
- `bark.lightning_receive` receive (receiving lightning payment)

These operations don't send funds externally, so `sent_to` will be empty.

### How do I track a specific payment?

1. **Filter by subsystem**: Check `subsystem.name` and `subsystem.kind` to identify the operation type
2. **Check destination**: Look in `sent_to[].destination` to match the payment method (address, invoice, offer)
3. **Monitor status**: Track the `status` field for state changes
4. **Verify completion**: Check `time.completed_at` to confirm when the movement finished

For lightning payments, you can also match by `metadata.payment_hash`.

### Why would `exited_vtxos` be populated?

VTXOs are marked for emergency exit when:
- Lightning HTLC VTXOs can't be swapped/revoked and are near expiry (see `bark.lightning_send` and
  `bark.lightning_receive` notes)

When populated, these VTXOs are no longer spendable offchain and will be claimed onchain through the exit process.

### Do all movements modify VTXOs?

Yes, nearly all movements result in VTXO changes, even failed ones:
- `input_vtxos`: VTXOs consumed (locked/spent)
- `output_vtxos`: New VTXOs created (change, received, refreshed)
- `exited_vtxos`: VTXOs marked for exit

Even if the wallet balance doesn't change (`effective_balance_sat == 0`), VTXOs can be consumed and new ones created
with equal values.

### What does `offchain_fee_sat` represent?

`offchain_fee_sat` represents fees paid to the ark protocol for various operations, such as:
- Round participation fees (offboard, send_onchain)
- Refresh fees
- Some arkoor sends (if applicable)
- Lightning routing fees (if any)

This does NOT include:
- Bitcoin network fees (found in `metadata.onchain_fee_sat` for board operations)

The `effective_balance_sat` field includes `offchain_fee_sat` in its calculation.
