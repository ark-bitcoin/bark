# Coding Conventions
This might be controversial, but the primary objective of your code is to be
understood by your fellow developers. Running correctly is secondary to that.
The reasoning is that correct, but hard-to-understand code might work, but will
probably not get proper review (we're not all big-brains) and will become hard
to maintain. On the other hand, easy-to-understand code is easy to review and
any bugs you might have made will be caught by your reviewers.

What does this mean in practice:
- Use declarative names: both function and variable names.
- Use comments: explain reasoning of more complex parts in common language.
- Use formatting: the way you format code can significantly influence
  readability, use this as a tool to your advantage.

Yes, this does mean that we don't enforce code formatting and don't try to "have
0 clippy warnings". rustfmt produces notoriously horrendous code that is at
times cringe-inducingly space-inefficient and often hinders readability and
reviewability of code. Blind attempts to remove all clippy warnings has been a
common source of introducing subtle bugs/breaking changes.

As a rule of thumb, you can usually look at similar code to see what our style
is. Things like function signature formatting, `where` blocks, generics, etc.
can just be deduced from surrounding code.

We are humans, not robots. We write different code, it's fine. It's ok to
comment on readability/coherence, but avoid being pedantic.

## Table of Contents

- [Core Style](#core-style)
- [Serialization](#serialization)

## Core Style

Typically, we follow the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/index.html#formatting-conventions)
with certain exceptions. Some of the most common and important exceptions are as
follows:

### Tabs and Spacing

- Use tabs for indentation so that each dev can choose their own indentation
  size.
- We offer some leniency in column width, the following can be longer than 100
characters with an assumed tab width of 4 where it makes sense. Please use your 
best judgment.
    - Logging statements which are purely prints.
    - Some testing code, most notably assert statements and test method names.

### Modules & Imports
1. Module definitions should be before imports, the order should be public,
semi-public, e.g. `pub(crate)`, then private in alphabetical order. Use a line
break after the final module definition to keep them separate from import 
statements.
2. Organize imports, first grouped by `pub use`, then `pub(..) use`, `use`,
etc. Preferably order imports alphabetically and group with line breaks in the
following order:
   - stdlib
   - external deps
   - internal deps (our own crates)
   - crate deps (same crate)

Here's an example for a source file in the `bark` crate, the comments are for
illustrative purposes only so you don't need to add them in real code:
```rust
pub mod network;
pub mod time;
pub(crate) mod log;
mod error;
mod types;

pub use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};

pub(crate) use bitcoin_ext::rpc::{BitcoinRpcExt, TxStatus};

use std::borrow::Borrow; // First private stdlib dep
use std::collections::{HashMap, HashSet};
use std::time::UNIX_EPOCH;

use anyhow::Context; // First private external dep
use bdk_bitcoind_rpc::{BitcoindRpcErrorExt, NO_EXPECTED_MEMPOOL_TXIDS};
use bdk_wallet::chain::{BlockId, ChainPosition, CheckPoint};
use bitcoin::{Amount, Block, BlockHash};
use log::{debug, info, warn};

use bitcoin_ext::{BlockHeight, BlockRef}; // First private internal dep

use crate::onchain; // First private crate dep
```

## Serialization
We typically take advantage of `Serialize` and `Deserialize` traits to make
serialization and deserialization as seamless as possible. There are exceptions
to this as highlighted below:
1. Bitcoin transactions should be serialized as hex
2. Enums should use `rename_all = "kebab-case"`
3. Enums with struct variants should use `tag = "type"`
4. Enums with struct variants should always use named parameters, otherwise
the code may compile but error during serialization

Here's an example of different types:
```rust
#[derive(Deserialize, Serialize)]
pub struct NoSpecialRules {
    pub txid: bitcoin::Txid,
    pub block: bitcoin_ext::BlockRef,
}

#[derive(Deserialize, Serialize)]
pub struct TransactionStruct {
    // Serialize to hex when serializing to text formats such as JSON
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
    pub tx: bitcoin::Transaction,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnumWithNoStructVariant {
    First, 
    Second,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EnumWithStructVariant {
    First,
    //Second(bitcoin::BlockHeight), <----- Disallowed
    Second { height: bitcoin::BlockHeight },
    Third { txid: bitcoin::Txid, block: bitcoin_ext::BlockRef },
}
```