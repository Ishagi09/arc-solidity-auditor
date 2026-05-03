# ⬡ Arc Solidity Auditor

> Catches Arc-specific Solidity bugs that standard tools like Slither and MythX completely miss.

[![Arc Network](https://img.shields.io/badge/Built%20for-Arc%20Network-00E5A0?style=flat-square)](https://arc.network)
[![EVM Compatible](https://img.shields.io/badge/EVM-Compatible-60A5FA?style=flat-square)](https://docs.arc.network/arc/references/evm-compatibility)
[![License: MIT](https://img.shields.io/badge/License-MIT-white?style=flat-square)](LICENSE)

---

## Why This Exists

When developers migrate Ethereum contracts to Arc, standard audit tools give them a false sense of security. Slither, MythX, and Hardhat don't know about Arc-specific behavior — so contracts deploy, look fine, and then silently break or get exploited.

This tool scans Solidity source code for **Arc-specific incompatibilities** before they become production bugs.

---

## What It Catches

| Severity | Issue | Impact |
|----------|-------|--------|
| 🔴 Critical | `block.prevrandao` always returns `0` | Randomness is instantly exploitable |
| 🔴 Critical | `selfdestruct()` restricted on Arc | Contract deployment reverts |
| 🟡 Warning | ETH denominations (`ether`, `gwei`, `msg.value`) | Wrong amounts — Arc uses USDC as native gas |
| 🟡 Warning | EIP-4844 blob transactions | Not supported on Arc, silent failure |
| 🟡 Warning | Strict `block.timestamp` comparisons | Sub-second blocks can share timestamps |
| 🟡 Warning | `.transfer()` / `.send()` patterns | Gas stipend behavior differs from Ethereum |
| 🔵 Info | `1e18` / `decimals()` assumptions | Native USDC = 18 dec, ERC-20 USDC = 6 dec — mixing causes 1e12x errors |
| 🔵 Info | `blockhash` / `block.difficulty` randomness | Weak source, worse on Arc's permissioned validators |

---

## Features

- **Paste & Scan** — paste any Solidity source, get instant results
- **Fetch by Address** — enter a verified contract address from Arc Testnet, auto-fetches source from [ArcScan](https://testnet.arcscan.app)
- **AI-Powered Explanations** — click any issue for a Claude-powered explanation of exactly what breaks on Arc and how to fix it
- **Compatibility Score** — 0–100 score based on severity of detected issues
- **Line-level highlighting** — issues mapped directly to line numbers in your code

---

## Live Demo

>🔗 Live Demo — coming soon

---

## Arc-Specific Context

Arc is an EVM-compatible Layer-1 blockchain built by Circle, purpose-built for stablecoin finance. While it supports Solidity and standard EVM tooling, several behaviors differ from Ethereum:

- **USDC is the native gas token** — not ETH
- **`block.prevrandao` = 0** — Arc has no beacon chain
- **Sub-second finality** — blocks finalize in <1s, timestamps can repeat
- **SELFDESTRUCT restricted** — to prevent accidental native USDC burns
- **USDC decimal duality** — native USDC (18 dec) vs ERC-20 USDC (6 dec)

Docs: [docs.arc.network/arc/references/evm-compatibility](https://docs.arc.network/arc/references/evm-compatibility)

---

## Tech Stack

- React + Vite
- Pattern-based static analysis (regex + AST-aware heuristics)
- Claude API for AI-powered explanations
- ArcScan (Blockscout) API for contract fetching

---

## Contributing

PRs welcome. If you find an Arc-specific compatibility issue not covered here, open an issue with:
1. The Solidity pattern
2. What breaks on Arc
3. The recommended fix

---

Built by [@Ishagi09](https://github.com/) · For the [Arc Network](https://arc.network) ecosystem

