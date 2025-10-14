![bark: Ark on bitcoin](https://codeberg.org/ark-bitcoin/bark/media/branch/master/assets/bark-header-white.jpg)

<div align="center">
<h1>Bark: Ark on bitcoin</h1>
<p>Fast, low-cost, self-custodial payments on bitcoin.</p>
</div>

<p align="center">
  <br />
  <a href="https://docs.second.tech">Docs</a> ·
  <a href="https://codeberg.org/ark-bitcoin/bark/issues">Issues</a> ·
  <a href="https://second.tech">Website</a> ·
  <a href="https://blog.second.tech">Blog</a> ·
  <a href="https://www.youtube.com/@2ndbtc">YouTube</a>
</p>

<div align="center">

[![Release](https://img.shields.io/gitea/v/release/ark-bitcoin/bark?label=release&gitea_url=https://codeberg.org)](https://codeberg.org/ark-bitcoin/bark/tags)
[![Project Status](https://img.shields.io/badge/status-experimental-red.svg)](https://codeberg.org/ark-bitcoin/bark)
[![License](https://img.shields.io/badge/license-CC0--1.0-blue.svg)](https://codeberg.org/ark-bitcoin/bark/LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=git)](https://codeberg.org/ark-bitcoin/bark/CONTRIBUTING.md)
[![Community](https://img.shields.io/badge/community-forum-blue?logo=discourse)](https://community.second.tech)

</div>
<br />

Bark is an implementation of the Ark protocol on bitcoin, led by [Second](https://second.tech).

# A tour of Bark

Integrating the Ark-protocol offers

- 🏃‍♂️ **Smooth boarding**: No channels to open, no on-chain setup required—create a wallet and start transacting
- 🤌 **Simplified UX**: Send and receive without managing channels, liquidity, or routing
- 🌐 **Universal payments**: Send Ark, Lightning, and on-chain payments from a single off-chain balance
- 🔌 **Easier integration**: Client-server architecture reduces complexity compared to P2P protocols
- 💸 **Lower costs**: Instant payments at a fraction of on-chain fees
- 🔒 **Self-custodial**: Users maintain full control of their funds at all times

This guide puts focus on how to use the Rust-API and assumes
some basic familiarity with the Ark protocol. We refer to the
[protocol docs](http://docs.second.tech/ark-protocol) for an introduction.

## Creating an Ark wallet

The user experience of setting up an Ark wallet is pretty similar
to setting up an onchain wallet. You need to provide a [bip39::Mnemonic] which
can be used to recover funds. Typically, most apps request the user
to write down the mnemonic or ensure they use another method for a secure back-up.

The user can select an Ark server and a [onchain::ChainSource] as part of
the configuration. The example below configures

You will also need a place to store all [ark::Vtxo]s on the users device.
We have implemented [SqliteClient] which is a sane default on most devices.
However, it is possible to implement a [BarkPersister] if you have other
requirements.

The code-snippet below shows how you can create a [Wallet].

```no_run
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use bark::{Config, onchain, SqliteClient, Wallet};

const MNEMONIC_FILE : &str = "mnemonic";
const DB_FILE: &str = "db.sqlite";

#[tokio::main]
async fn main() {
  // Pick the bitcoin network that will be used
  let network = bitcoin::Network::Signet;

  // Configure the wallet
  let config = Config {
    server_address: String::from("https://ark.signet.2nd.dev"),
    esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
    ..Config::network_default(network)
  };


  // Create a sqlite database
  let datadir = PathBuf::from("./bark");
  let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());

  // Generate and seed and store it somewhere
  let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
  fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await.unwrap();

  let wallet = Wallet::create(
    &mnemonic,
    network,
    config,
    db,
    false
  ).await.unwrap();
}
```

## Opening an existing Ark wallet

The [Wallet] can be opened again by providing the [bip39::Mnemonic] and
the [BarkPersister] again. Note, that [SqliteClient] implements the [BarkPersister]-trait.

```no_run
# use std::sync::Arc;
# use std::path::PathBuf;
# use std::str::FromStr;
#
# use bip39;
# use tokio::fs;
#
# use bark::{Config, SqliteClient, Wallet};
#
const MNEMONIC_FILE : &str = "mnemonic";
const DB_FILE: &str = "db.sqlite";

#[tokio::main]
async fn main() {
  let datadir = PathBuf::from("./bark");
  let config = Config {
    server_address: String::from("https://ark.signet.2nd.dev"),
    esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
    ..Config::network_default(bitcoin::Network::Signet)
  };

  let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
  let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
  let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
  let wallet = Wallet::open(&mnemonic, db, config).await.unwrap();
}
```

## Receiving coins

For the time being we haven't implemented an Ark address type (yet). You
can send funds directly to a public key.

If you are on signet and your Ark server is [https://ark.signet.2nd.dev](https://ark.signet.2nd.dev),
you can request some sats from our [faucet](https://signet.2nd.dev).

```no_run
# use std::sync::Arc;
# use std::str::FromStr;
# use std::path::PathBuf;
#
# use tokio::fs;
#
# use bark::{Config, Wallet, SqliteClient};
#
# const MNEMONIC_FILE : &str = "mnemonic";
# const DB_FILE: &str = "db.sqlite";
#
# async fn get_wallet() -> Wallet {
#   let datadir = PathBuf::from("./bark");
#   let config = Config::network_default(bitcoin::Network::Signet);
#
#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
#   Wallet::open(&mnemonic, db, config).await.unwrap()
# }
#

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let wallet = get_wallet().await;
  let address: ark::Address = wallet.new_address()?;
  Ok(())
}
```

## Inspecting the wallet

An Ark wallet contains [ark::Vtxo]s. These are just like normal utxos
in a bitcoin wallet. They just haven't been confirmed on chain (yet).
However, the user remains in full control of the funds and can perform
a unilateral exit at any time.

The snippet below shows how you can inspect your [bark::WalletVtxo]s.

```no_run
# use std::sync::Arc;
# use std::str::FromStr;
# use std::path::PathBuf;
#
# use tokio::fs;
#
# use bark::{Config, SqliteClient, Wallet};
#
# const MNEMONIC_FILE : &str = "mnemonic";
# const DB_FILE: &str = "db.sqlite";
#
# async fn get_wallet() -> Wallet {
#   let datadir = PathBuf::from("./bark");
#
#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
#
#   let config = Config::network_default(bitcoin::Network::Signet);
#
#   Wallet::open(&mnemonic, db, config).await.unwrap()
# }
#

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut wallet = get_wallet().await;

  // The vtxo's command doesn't sync your wallet
  // Make sure your app is synced before inspecting the wallet
  wallet.sync().await;

  let vtxos: Vec<bark::WalletVtxo> = wallet.vtxos().unwrap();
  Ok(())
}
```

Use [Wallet::offchain_balance] if you are only interested in the balance.

## Participating in a round

You can participate in a round to refresh your coins. Typically,
you want to refresh coins which are soon to expire or you might
want to aggregate multiple small vtxos to keep the cost of exit
under control.

As a wallet developer you can implement your own refresh strategy.
This gives you full control over which [ark::Vtxo]s are refreshed and
which aren't.

This example uses [RefreshStrategy::must_refresh] which is a sane
default that selects all [ark::Vtxo]s that must be refreshed.

```no_run
# use std::sync::Arc;
# use std::str::FromStr;
# use std::path::PathBuf;
#
# use tokio::fs;
#
# use bark::{Config, Wallet, SqliteClient};
#
# const MNEMONIC_FILE : &str = "mnemonic";
# const DB_FILE: &str = "db.sqlite";
#
# async fn get_wallet() -> Wallet {
#   let datadir = PathBuf::from("./bark");
#
#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
#
#   let config = Config::network_default(bitcoin::Network::Signet);
#
#   Wallet::open(&mnemonic, db, config).await.unwrap()
# }
#
use bark::vtxo_selection::RefreshStrategy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let wallet = get_wallet().await;

  // Select all vtxos that refresh soon
  let tip = wallet.chain.tip().await?;
  let fee_rate = wallet.chain.fee_rates().await.fast;
  let strategy = RefreshStrategy::must_refresh(&wallet, tip, fee_rate);

  let vtxos = wallet.spendable_vtxos_with(&strategy)?
    .into_iter().map(|v| v.vtxo).collect::<Vec<_>>();
  wallet.refresh_vtxos(vtxos).await?;
  Ok(())
}
```
