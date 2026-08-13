# Writing Style and Vocabulary

Write technical content in this project in Simplified Technical English (STE).
Follow the principles in this guide. You do not need to read the full STE
specification.

This guide applies to all text you write. This includes documentation,
comments, docstrings, changelogs, commit messages, and user-facing strings.

## Simplified Technical English Principles

This guide follows Simplified Technical English (STE). Use these principles when
you write:

- Use short sentences. Put one idea in each sentence.
- Use active voice.
- Use the imperative for instructions.
- Use "must" for requirements. Do not use "should" or "have to".
- Use present tense.
- Use consistent terminology.
- Use articles (a, an, the).
- Do not use contracted forms.
- Do not use -ing forms when a simple verb is enough.
- Do not use phrasal verbs when a single-word verb is enough.
- Do not use ambiguous words.
- Do not use slang, idioms, or figures of speech.

## Vocabulary

Use the terms in the tables below. Do not use the terms in the "Don't use"
column.

### Ark terms

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
| board VTXO, refresh VTXO | mint VTXOs, issue VTXOs | VTXOs are not created out of thin air. Name the process. |
| grant HTLCs | mint HTLCs | Name the process |
| emergency exit | unilateral exit | Recently renamed across the project |
| onto (Ark) | into (Ark) | "onto the Ark protocol", not "into" |
| registers | marks | For exit start: "registers VTXOs for emergency exit" |

VTXOs are not created out of thin air. A client boards an on-chain UTXO into a
VTXO. A client and server refresh an existing VTXO. Do not use language that
falsely suggests the server creates VTXOs from nothing.

### Bitcoin terms

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

### Lightning terms

| Use | Don't use | Why |
|-----|-----------|-----|
| Lightning Network | Lightning network | Proper noun |
| Lightning Service Provider, LSP | lightning service provider | |
| Core Lightning, CLN | c-lightning | Rebranded |

### General writing

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

- Write out one through ten.
- Use digits for 11 and above.
- Use digits for all technical instructions.
- Be consistent within each document.

## Style

### Ark protocol references

- Use "the Ark protocol" when you use the full name. Include the word "the".
- You do not need "the" before "Ark" when you use "Ark" on its own.
  - Correct: "the Ark protocol enables..." or "Ark enables..."
  - Incorrect: "Ark protocol enables..."

### Bark references

- Use "Bark" (capitalized) in prose.
- Use "bark" (lowercase) for technical artifacts. These include CLI commands,
  code, and paths.
  - Prose: "Bark is Second's implementation of the Ark protocol"
  - Technical: "run `bark send` to send a payment"

### Atomic operations

- Ark operations are atomic. Forfeit and output happen in the same transaction.
- Do not write that users swap or exchange assets.
- Do not use these words: "exchange", "swap", "in exchange for", "in return
  for", "traded for".
- Use these words instead: "forfeit and receive", "forfeit to deliver". You can
  also describe the atomic operation directly.
  - Correct: "Users forfeit old VTXOs and receive new ones"
  - Incorrect: "Users exchange old VTXOs for new ones"

### Formatting

- Use backticks for endpoint references (`` `progress` ``, `` `claim` ``).
- Use backticks for field references when the value helps the reader
  (`` `done: true` ``).
