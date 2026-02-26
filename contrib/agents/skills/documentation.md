# Documentation Skill

Vocabulary, terminology, and style guide for documentation, docstrings, and
comments.

## Vocabulary Guide

Use consistent terminology throughout all documentation.

### Ark Terms

| Use | Don't use | Why |
|-----|-----------|-----|
| Ark protocol | Ark Protocol | |
| Ark server | ASP, Ark Service Provider | Real words, not jargon |
| arkoor | Arkoor | Stylized lowercase |
| board | onboard, on-board | |
| offboard | off-board, off board | |
| in-round transaction | inround, in-round payment | "transaction" is more accurate |
| out-of-round transaction | out of round transaction | |
| VTXO | vtxo, Vtxo | |
| emergency exit | unilateral exit | Recently renamed across the project |
| onto (Ark) | into (Ark) | "onto the Ark protocol", not "into" |
| registers | marks | For exit start: "registers VTXOs for emergency exit" |

### Bitcoin Terms

| Use | Don't use | Why |
|-----|-----------|-----|
| bitcoin, sats | funds, crypto, assets, cryptocurrency | Be specific about what we're building |
| bitcoin (lowercase) | Bitcoin | Context is always clear |
| bitcoin (singular) | bitcoins, 6.15 bitcoins | Industry convention |
| sats (100 sats, 1 sat) | satoshi, satoshis | |
| UTXO | utxo | |
| multisig | multi-sig | Cleaner in UIs |
| singlesig | single-sig | |
| seed phrase | mnemonic, recovery phrase | Most widely understood |
| on-chain, off-chain | onchain, on chain | |
| layer 2 | Layer 2, layer two | |
| blockspace | block space | |
| feerate, "1 sat/vB" | fee rate, "2 sats/vB" | sat is singular in rates |
| co-sign | cosign | |
| double-spend | double spend | |
| hashrate | hash rate | |
| proof of work, PoW | proof-of-work | |
| xpub, ypub, zpub | xPub, XPUB | Community consensus |
| 2-of-3, m-of-n | 2 of 3, 2of3 | |
| Bitcoin Script | bitcoin script | Exception: proper noun |
| bitcoin mainnet | Bitcoin Mainnet | |
| bitcoin testnet | Testnet | |
| label | note, memo | Traditional bitcoin term |
| hardware wallet | hardware device | "device" is ambiguous |
| wallet app | wallet (for software) | "wallet" means keys/addresses |

### Lightning Terms

| Use | Don't use | Why |
|-----|-----------|-----|
| Lightning Network | Lightning network | Proper noun |
| Lightning Service Provider, LSP | lightning service provider | |
| Core Lightning, CLN | c-lightning | Rebranded |

### General Writing

| Use | Don't use | Why |
|-----|-----------|-----|
| you, your | the user | More relatable |
| specified | given | "the specified address", not "the given address" |
| trade-off | tradeoff | |
| backend, frontend | back-end, front-end | |
| co-founder | cofounder | |
| em dash (—) | spaced hyphens ( - ) | No spaces: `foo—bar` not `foo — bar` |
| sentence case headings | Title Case Headings | Cleaner |
| 5K, 5M, 5B | 5 thousand, 5m, 5mm | "mm" confuses people |

### Numbers

- Write out one through ten
- Use digits for 11 and above
- Use digits for all technical instructions
- Be consistent within each document

## Style Guide

### Ark protocol references

- Use "the Ark protocol" (with "the") when using the full name.
- Just "Ark" is fine on its own and does not require "the".
  - Correct: "the Ark protocol enables..." or "Ark enables..."
  - Incorrect: "Ark protocol enables..."

### Bark references

- Use "Bark" (capitalized) in prose and explanations.
- Use "bark" (lowercase) for technical artifacts: CLI commands, code, paths.
  - Prose: "Bark is Second's implementation of the Ark protocol"
  - Technical: "run `bark send` to send a payment"

### Atomic operations

Ark operations are atomic—forfeit and output happen in the same transaction.
Do not use language that implies swapping or exchanging different assets.

- Avoid: "exchange", "swap", "in exchange for", "in return for", "traded for"
- Prefer: "forfeit and receive", "forfeit to deliver", or describe the atomic
  operation directly
  - Correct: "Users forfeit old VTXOs and receive new ones"
  - Incorrect: "Users exchange old VTXOs for new ones"

### Formatting

- **Endpoint references**: Use backticks (`` `progress` ``, `` `claim` ``).
- **Field references**: Use backticks with the value where helpful
  (`` `done: true` ``).
