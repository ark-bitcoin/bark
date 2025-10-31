![bark: Ark on bitcoin](https://gitlab.com/ark-bitcoin/bark/-/raw/master/assets/bark-header-white.jpg)

<div align="center">
<h1>Bark: Ark on bitcoin</h1>
<p>Fast, low-cost, self-custodial payments on bitcoin.</p>
</div>

<p align="center">
  <br />
  <a href="https://docs.second.tech">Docs</a> ·
  <a href="https://gitlab.com/ark-bitcoin/bark/issues">Issues</a> ·
  <a href="https://second.tech">Website</a> ·
  <a href="https://blog.second.tech">Blog</a> ·
  <a href="https://www.youtube.com/@2ndbtc">YouTube</a>
</p>

<div align="center">

[![Release](https://img.shields.io/gitea/v/release/ark-bitcoin/bark?label=release&gitea_url=https://gitlab.com)](https://gitlab.com/ark-bitcoin/bark/tags)
[![Project Status](https://img.shields.io/badge/status-experimental-red.svg)](https://gitlab.com/ark-bitcoin/bark)
[![License](https://img.shields.io/badge/license-CC0--1.0-blue.svg)](https://gitlab.com/ark-bitcoin/bark/LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=git)](https://gitlab.com/ark-bitcoin/bark/CONTRIBUTING.md)
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

For setup and usage instructions, see the [Getting Started guide](https://docs.second.tech/getting-started/) or look at our [Rust API docs](https://docs.rs/bark-wallet)? 