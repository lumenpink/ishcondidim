# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Features
  - (crypto) pure Rust OpenPGP engine using `pgp` crate with modern Ed25519 signing and X25519 encryption
  - (keystore) automated server-side private key generation on-the-fly and persistent peer state machine
  - (autocrypt) Autocrypt Level 1 header formatting, parsing and Autocrypt-Gossip generation
  - (encryption) opportunistic PGP/MIME outbound encryption with automatic plain downgrade if peer removes Autocrypt
  - (decryption) server-side inbound PGP/MIME decryption with verification status banner
  - (anti-spoofing) validation banner with configurable `security_word` and plain-text spoofing sanitizer
  - (milter) dual UNIX domain socket and TCP listener for Postfix integration with SMFIC event handling
  - (config) hierarchical TOML configuration (`default` -> `domains` -> `senders`) with hot-reload via `notify`
  - (deploy) systemd service unit with hardened sandboxing and example configuration
  - (site) beachy pastel documentation portal deployable to Cloudflare Workers (`ixcondidim.2lp.in`)
