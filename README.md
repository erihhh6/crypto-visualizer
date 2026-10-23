# Crypto Visualizer

[![CI](https://github.com/erihhh6/crypto-visualizer/actions/workflows/ci.yml/badge.svg)](https://github.com/erihhh6/crypto-visualizer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> An interactive Python GUI application that makes cryptographic concepts visible and tangible.

![Demo](assets/demo.gif)

---

## What this visualizes

- **AES Modes** — ECB, CBC, CTR, GCM drawn as per-block data flow (IV and CBC chaining, counters and keystream, the GCM tag), with hover tooltips and click-to-inspect
- **Mode comparison** — one message and key through all four modes; equal 16-byte blocks share a colour, so ECB's repeated blocks stand out, and each mode's length, IV/counter and tag are listed
- **Tamper Lab** — decrypt with wrong keys (one, or 20,000 to measure the padding check's ~1-in-255 false accepts) and edit a message without the key by XORing its ciphertext: CTR applies the edit exactly, CBC garbles the block before, ECB only garbles, GCM refuses
- **ECB Penguin Attack** — open any image (PNG, JPEG, BMP, …) and see why ECB mode is dangerous: structural patterns survive encryption. Large images are shrunk to 512 px first, and the views scale with the display's DPI
- **Key Exchange** — Diffie-Hellman (3072-bit RFC 3526 group 15 by default, which matches P-256's 128-bit security, or 2048-bit group 14) and ECDH (SECP256R1), told one step at a time (Next/Prev, ←/→ keys or autoplay) with every value marked public, private (never shown) or secret, both ending with an AES-256 key derived by HKDF-SHA256; ECDH is replayed on a toy curve (y² = x³ − 3x + 10 mod 97) small enough to plot every point
- **DH vs ECDH size comparison** — equivalent security levels at dramatically different key sizes

The app follows your system's light or dark theme, switching live, and all its text meets WCAG AA contrast (4.5:1) in both. Every control still fits in the smallest window (900×600); the block diagram and the Tamper Lab scroll there. Enter in the plaintext or key field encrypts, and in the Tamper Lab's "Replace … with …" fields it makes the edit.

---

## Why it matters

AES mode selection is one of the most common cryptographic mistakes in real software — ECB mode leaks structure even when the key is strong. Key exchange protocols underpin every TLS connection, SSH session, and secure messaging app. Seeing these algorithms execute step by step, with real cryptographic values, builds the intuition needed to make correct security decisions.

---

## Installation

```bash
pip install -r requirements.txt
python main.py
```

Requires Python 3.11+.

---

## Development

```bash
pip install -r requirements-dev.txt

python -m pytest --cov   # tests + coverage (any warning fails the run)
python -m ruff check .   # lint
python -m ruff format .  # format
python -m mypy           # strict type check
```

CI runs the same checks on every push and pull request, with tests on
Python 3.11–3.15. Tool configuration lives in `pyproject.toml`.

The AES modes are checked against published known answers: FIPS 197
Appendix B, SP 800-38A Appendix F (ECB, CBC, CTR) and the test cases of the
GCM specification, down to what each block puts through AES, which is what
the block diagram shows.

GUI tests (`tests/gui/`) open real windows, so expect brief flashes on your
desktop; CI runs them under `xvfb`, and without any display they are skipped.
Known bugs are recorded as tests marked `known_bug(...)` (strict expected
failures) until the commit that fixes them removes the marker.

---

## Concepts demonstrated

| Concept | What the app shows | Reference |
|---|---|---|
| AES-ECB | Identical plaintext blocks produce identical ciphertext blocks | NIST SP 800-38A §6.1 |
| AES-CBC | Each block XOR'd with previous ciphertext — patterns disappear | NIST SP 800-38A §6.2 |
| AES-CTR | Stream cipher mode; no padding needed; parallelisable | NIST SP 800-38A §6.5 |
| AES-GCM | Authenticated encryption; includes 128-bit integrity tag | NIST SP 800-38D |
| ECB Penguin Attack | Encrypting an image's pixels with ECB preserves its visual structure | The "ECB penguin": [Tux encrypted with ECB](https://commons.wikimedia.org/wiki/File:Tux_ecb.jpg) by Larry Ewing and Lunkwill |
| Diffie-Hellman | Public/private value exchange; shared secret via modular exponentiation | RFC 3526 |
| ECDH | Same idea on an elliptic curve; much smaller keys for same security | RFC 8422 |
| Key size equivalence | 256-bit ECDH ≈ 3072-bit DH ≈ 128-bit symmetric security | NIST SP 800-57 Table 2 |
| Key derivation | A shared secret is not a key: HKDF extracts and expands it into one | RFC 5869 |

---

## Project structure

```
crypto-visualizer/
├── main.py                    # Entry point
├── modules/
│   ├── aes_modes.py           # AES ECB/CBC/CTR/GCM encrypt/decrypt + per-block detail
│   ├── tamper.py              # Wrong-key and ciphertext-editing experiments
│   ├── key_exchange.py        # DH + ECDH step-by-step + comparison
│   └── toy_curve.py           # Curve arithmetic and ECDH on a plottable toy curve
├── gui/
│   ├── main_window.py         # CustomTkinter window + tab view
│   ├── aes_tab.py             # AES tab: controls, encrypt/decrypt, panel layout
│   ├── block_canvas.py        # Per-block data-flow diagram, tooltips and details
│   ├── image_demo.py          # ECB vs CBC on an image's pixels
│   ├── mode_comparison.py     # One message in all four modes, equal blocks coloured
│   ├── tooltip.py             # Pointer-following tooltip window
│   ├── palette.py             # Light/dark colour pairs, readable button theme
│   ├── layout.py              # Text that wraps to the width it is given
│   ├── tamper_tab.py          # Tamper Lab: wrong keys and forged edits, per mode
│   ├── key_exchange_tab.py    # Step animator and key-size comparison table
│   └── exchange_plot.py       # DH message flow, or the toy curve's ECDH points
├── assets/
│   └── sample.bmp             # Test image for ECB attack demo
└── requirements.txt
```

---

## References

- **NIST FIPS 197** — Advanced Encryption Standard (AES): https://csrc.nist.gov/publications/detail/fips/197/final
- **NIST SP 800-38A** — Block Cipher Modes of Operation (ECB, CBC, CTR): https://csrc.nist.gov/publications/detail/sp/800-38a/final
- **NIST SP 800-38D** — GCM Mode: https://csrc.nist.gov/publications/detail/sp/800-38d/final
- **McGrew & Viega, *The Galois/Counter Mode of Operation (GCM)*** — the specification submitted to NIST, whose test cases the tests use; listed on NIST's modes development page: https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
- **RFC 3526** — More Modular Exponential (MODP) Diffie-Hellman groups for IKE: https://www.rfc-editor.org/rfc/rfc3526
- **RFC 8422** — Elliptic Curve Cryptography (ECC) Cipher Suites for TLS: https://www.rfc-editor.org/rfc/rfc8422
- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation Function (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- **NIST SP 800-57** — Recommendation for Key Management: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **PyCA cryptography** — https://cryptography.io/en/latest/
