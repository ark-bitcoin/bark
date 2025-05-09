# Bark: Ark on Bitcoin

An implementation for the Ark protocol on Bitcoin. You will find an 
ASP server named `aspd`, a client called `bark` and a set of libraries
that contain all primitives used for this implementation.

> [!WARNING]
> This repository contains experimental code. 
> Using this implementation in production with real bitcoin 
> is reckless and can result in loss of funds.
>
> Please be aware that
> - Updating bark/aspd may corrupt your wallet. At this stage we prioritize development velocity over backward compatibility.
> - This code contains known bugs and vulnerabilities that can result in loss of funds.

## What is Ark??

Ark is a Layer 2 protocol that enables faster and cheaper transactions on bitcoin.

For more info check out

- [Ark protocol website](https://ark-protocol.org)
- our [technical docs](https://docs.second.tech/protocol/intro).

## Getting started

Our [guide](https://docs.second.tech/getting-started/) that explains how to [compile from source](https://docs.second.tech/getting-started/optional/compile-from-source/) 
and run an ASP using [regtest](https://docs.second.tech/run-ark-server/).

## Questions or issues

If you run into issues let us know. We run our issue-tracker on [codeberg](https://codeberg.org/ark-bitcoin/bark).

## Security policy and responsible disclosure

The code is experimental and must not be used in production.

If you happen to find a vulnerability we invite you to file a public issue.

