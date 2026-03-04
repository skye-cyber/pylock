[![PyPI Version](https://img.shields.io/pypi/v/pylock-suite?style=for-the-badge&color=blue)](https://pypi.org/project/pylock-suite/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)
[![Build Status](https://img.shields.io/github/actions/workflow/status/skye-cyber/pylock/ci.yml?branch=main&style=for-the-badge)](https://github.com/skye-cyber/pylock/actions)
[![Downloads](https://img.shields.io/pypi/dm/pylock-suite?style=for-the-badge&color=green)](https://pypi.org/project/pylock-suite/)


# 🔐 PyLock

**Modern, Beautiful, Secure File Encryption**

*Encrypt and decrypt files with style. Built with Click and Rich for a delightful CLI experience.*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Ciphers](#available-ciphers) • [Documentation](https://github.com/skye-cyber/pylock/wiki)
---
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyLock · python file encryption toolkit</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            background: linear-gradient(145deg, #0b0e18 0%, #1a1f2f 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Roboto', sans-serif;
            padding: 1.5rem;
        }

        /* main banner card */
        .pylock-banner {
            max-width: 1040px;
            width: 100%;
            background: rgba(18, 22, 36, 0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(90, 150, 255, 0.2);
            border-radius: 3.5rem 2rem 3.5rem 2rem;
            box-shadow: 0 30px 50px -20px rgba(0, 0, 0, 0.8), 
                        0 0 0 1px rgba(75, 130, 255, 0.15) inset,
                        0 0 30px rgba(60, 160, 255, 0.2);
            padding: 2.2rem 2.8rem;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            transition: all 0.3s ease;
        }

        /* left content — text area */
        .banner-info {
            flex: 2 1 300px;
            padding-right: 1.8rem;
        }

        .pylock-label {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(45, 85, 255, 0.12);
            border: 1px solid rgba(65, 150, 255, 0.3);
            border-radius: 60px;
            padding: 0.4rem 1.2rem 0.4rem 0.9rem;
            margin-bottom: 1.2rem;
            backdrop-filter: blur(4px);
        }

        .lock-mini {
            color: #7ab5ff;
            font-size: 1.3rem;
            line-height: 1;
            filter: drop-shadow(0 0 5px #3f9eff);
        }

        .label-text {
            font-weight: 500;
            font-size: 0.9rem;
            letter-spacing: 0.5px;
            color: #b5d0ff;
            text-transform: uppercase;
            border-left: 1px solid rgba(110, 170, 255, 0.4);
            padding-left: 10px;
        }

        .label-text strong {
            color: white;
            font-weight: 600;
            margin-right: 4px;
        }

        h1 {
            font-size: 4.2rem;
            font-weight: 800;
            line-height: 1;
            letter-spacing: -1px;
            background: linear-gradient(135deg, #ffffff 0%, #c7e0ff 80%);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            text-shadow: 0 2px 10px rgba(30, 140, 255, 0.4);
            margin-bottom: 0.6rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .python-badge {
            background: #3776ab;
            padding: 0.25rem 1rem;
            border-radius: 40px;
            font-size: 1rem;
            font-weight: 600;
            color: #ffde57;
            letter-spacing: 0.3px;
            border: 1px solid #4b8bbd;
            box-shadow: 0 2px 8px #1f3850;
            vertical-align: middle;
            margin-left: 8px;
        }

        .tagline {
            font-size: 1.5rem;
            font-weight: 400;
            color: #b6caf5;
            margin-bottom: 2rem;
            border-left: 4px solid #3e7cff;
            padding-left: 1.4rem;
            background: linear-gradient(90deg, rgba(70, 130, 255, 0.1), transparent);
            line-height: 1.4;
        }

        .feature-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 1.2rem 2rem;
            margin: 2rem 0 1.5rem;
        }

        .feature-item {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.1rem;
            font-weight: 500;
            color: #d5e5ff;
            background: rgba(10, 20, 45, 0.4);
            padding: 0.2rem 1.2rem 0.2rem 0.6rem;
            border-radius: 30px;
            border: 1px solid rgba(90, 160, 255, 0.15);
            backdrop-filter: blur(2px);
        }

        .feature-icon {
            background: #1a3155;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #7fb9ff;
            border: 1px solid #315fa0;
        }

        .cta-section {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 1.5rem;
            margin-top: 2rem;
        }

        .btn {
            background: linear-gradient(165deg, #1d3b70, #10233f);
            border: none;
            padding: 0.9rem 2.3rem;
            border-radius: 60px;
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
            letter-spacing: 0.3px;
            box-shadow: 0 8px 0 #0c1628, 0 10px 20px rgba(0, 30, 100, 0.4);
            cursor: default;
            transition: 0.1s ease;
            border: 1px solid #4171c7;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-shine {
            background: linear-gradient(165deg, #194785, #0f2d5a);
            box-shadow: 0 8px 0 #0a1a30, 0 10px 25px #002856, 0 0 15px #3e80ff;
        }

        .code-snippet {
            font-family: 'Fira Code', 'JetBrains Mono', monospace;
            background: #0d1424;
            padding: 0.65rem 1.5rem;
            border-radius: 40px;
            font-size: 1.1rem;
            border: 1px solid #3165b0;
            color: #c3ddff;
            box-shadow: inset 0 4px 6px rgba(0,0,0,0.6);
            white-space: nowrap;
        }

        .code-snippet span {
            color: #ffcb6b;
        }

        /* right visual — python + lock + binary vibe */
        .banner-emblem {
            flex: 1 1 240px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
        }

        .shield-lock {
            font-size: 8.5rem;
            line-height: 1;
            filter: drop-shadow(0 10px 12px #00000066) drop-shadow(0 0 25px #2580ff);
            margin-bottom: 0.5rem;
            text-shadow: 0 0 30px #2580ff;
            position: relative;
            z-index: 2;
        }

        .binary-rain {
            display: flex;
            gap: 0.5rem;
            font-family: monospace;
            font-size: 1rem;
            font-weight: 600;
            color: #2f6fbb;
            background: rgba(0, 15, 30, 0.5);
            padding: 0.6rem 1.2rem;
            border-radius: 50px;
            backdrop-filter: blur(6px);
            border: 1px solid #2b65a5;
            letter-spacing: 2px;
            transform: rotate(-1deg);
            box-shadow: 0 0 30px #003c9e30;
        }

        .binary-rain span {
            color: #6bb0ff;
            animation: flicker 3s infinite alternate;
        }

        @keyframes flicker {
            0% { opacity: 0.4; text-shadow: 0 0 2px #5588ff; }
            100% { opacity: 1; text-shadow: 0 0 10px #95c2ff; }
        }

        /* small footer line */
        .os-label {
            margin-top: 1.5rem;
            font-size: 0.85rem;
            color: #6279b0;
            display: flex;
            gap: 10px;
            letter-spacing: 0.3px;
        }

        .os-label span {
            color: #a3beff;
        }

        /* responsive */
        @media (max-width: 750px) {
            .pylock-banner {
                padding: 1.8rem;
                border-radius: 2.5rem 1.5rem 2.5rem 1.5rem;
            }
            h1 {
                font-size: 3rem;
            }
            .tagline {
                font-size: 1.2rem;
            }
            .btn {
                padding: 0.7rem 1.8rem;
                font-size: 1.1rem;
            }
            .shield-lock {
                font-size: 6rem;
            }
        }

        @media (max-width: 550px) {
            .pylock-banner {
                flex-direction: column;
                text-align: center;
            }
            .banner-info {
                padding-right: 0;
            }
            .tagline {
                border-left: none;
                border-top: 4px solid #3e7cff;
                padding-left: 0;
                padding-top: 1rem;
            }
            .feature-grid {
                justify-content: center;
            }
            .cta-section {
                justify-content: center;
            }
        }

        /* extra decorative */
        .glow {
            background: radial-gradient(circle at 70% 30%, #1f4f9e20, transparent 60%);
        }
    </style>
</head>
<body>
    <div class="pylock-banner">
        <!-- left side: all text & features -->
        <div class="banner-info">
            <div class="pylock-label">
                <span class="lock-mini">🔒</span>
                <span class="label-text"><strong>PyLock</strong> · v2.5.1</span>
            </div>

            <h1>
                PyLock
                <span class="python-badge">🐍 ⚡</span>
            </h1>
            <div class="tagline">
                Python file encryption toolkit.<br> 
                <span style="font-size: 1rem; color: #95b5f0;">authenticated · simple · battle‑tested</span>
            </div>

            <div class="feature-grid">
                <div class="feature-item">
                    <span class="feature-icon">🔐</span> AES‑256‑GCM
                </div>
                <div class="feature-item">
                    <span class="feature-icon">📁</span> multi‑file glob
                </div>
                <div class="feature-item">
                    <span class="feature-icon">⚙️</span> key derivation (Argon2)
                </div>
                <div class="feature-item">
                    <span class="feature-icon">🕵️</span> stealth mode
                </div>
            </div>

            <div class="cta-section">
                <div class="btn btn-shine">
                    <span>🔑</span> pip install pylock
                </div>
                <div class="code-snippet">
                    <span>$</span> pylock encrypt secrets/ -o vault.pyl
                </div>
            </div>

            <div class="os-label">
                <span>🐧 linux</span> <span> macOS</span> <span>⊞ windows</span> · 100% pure python
            </div>
        </div>

        <!-- right side: big lock + binary background -->
        <div class="banner-emblem">
            <div class="shield-lock">
                🔒🐍🔒
            </div>
            <div class="binary-rain">
                <span>0</span><span>1</span><span>0</span><span>0</span><span>1</span><span>0</span><span>1</span>
                <span>1</span><span>0</span><span>1</span><span>1</span><span>0</span>
                <span style="color:#7bb3ff;">⇆</span>
                <span>1</span><span>0</span><span>1</span><span>0</span><span>0</span><span>1</span>
            </div>
            <!-- tiny key icon (muted) -->
            <div style="margin-top: 18px; opacity: 0.6; font-size: 1.2rem; color: #5880b0;">⚿ ⚿ ⚿</div>
        </div>
    </div>

    <!-- just a small signature (not part of banner) to show it's HTML/CSS demo, but we keep it minimal -->
    <div style="position: fixed; bottom: 10px; right: 20px; color: #2f4b7a; font-size: 0.8rem; opacity: 0.4; pointer-events: none;">
        pylock · encryption toolkit banner
    </div>
</body>
</html>
---

## ✨ Features

- 🎨 **Beautiful Interface** — Rich terminal output with progress bars, tables, and colors
- 🔒 **Modern Cryptography** — AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP, and more
- 📁 **File & Folder Support** — Encrypt individual files or entire directories
- 🗝️ **Smart Key Management** — Automatic key generation with secure storage
- 🔍 **Metadata Preservation** — Store encryption info for seamless decryption
- 🛡️ **Process Locking** — Prevent concurrent operations from corrupting data
- 🎓 **Educational Ciphers** — Classical ciphers (Caesar, Vigenère, Playfair) for learning
- ⚡ **High Performance** — Hybrid encryption for large files, streaming support

---

## 🚀 Installation

### From PyPI (Recommended)

```bash
pip install pylock-suite
```

### From Source

```bash
git clone https://github.com/skye-cyber/pylock.git
cd pylock
pip install -e .
```

### Development Install

```bash
pip install -e ".[dev]"
```

---

## 🎯 Quick Start

### Encrypt a File

```bash
# Interactive mode (prompts for password)
pylock encrypt secret.txt

# With explicit options
pylock encrypt document.pdf --cipher aes-256-gcm --password "mypassword"

# Short alias
pl encrypt photo.jpg -c chacha20
```

### Decrypt a File

```bash
# Interactive mode
pylock decrypt secret.txt.locked

# With key file
pylock decrypt backup.zip.locked --key-file key.pem

# Specify output
pylock decrypt data.enc -o decrypted.data
```

### Interactive Mode

```bash
pylock interactive
```

---

## 📖 Usage

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress non-error output |
| `--version` | Show version and exit |

### Commands

#### `encrypt`
Encrypt files or folders.

```bash
pylock encrypt [OPTIONS] PATH

Options:
  -c, --cipher TEXT       Cipher to use (default: aes-256-gcm)
  -p, --password TEXT     Encryption password
  -k, --key-file PATH     Save key to file
  -o, --output PATH       Output file/directory
  --no-compress           Disable compression
```

#### `decrypt`
Decrypt files or folders.

```bash
pylock decrypt [OPTIONS] PATH

Options:
  -p, --password TEXT     Decryption password
  -k, --key-file PATH     Read key from file
  -o, --output PATH       Output file/directory
  --brute-force           Attempt brute force (requires --wordlist)
  -w, --wordlist PATH     Wordlist for brute force
```

#### `list-ciphers`
Display available ciphers and their properties.

```bash
pylock list-ciphers
```

#### `generate-key`
Generate encryption keys (especially for RSA).

```bash
pylock generate-key --cipher rsa -o mykey.pem
```

#### `verify`
Check if a file is encrypted and display metadata.

```bash
pylock verify mystery.file
```

#### `interactive`
Launch guided interactive mode.

```bash
pylock interactive
```

---

## 🔐 Available Ciphers

| Cipher | Security | Type | Best For |
|--------|----------|------|----------|
| `aes-256-gcm` | 🔒 Modern (Recommended) | Symmetric | General purpose, hardware accelerated |
| `chacha20-poly1305` | 🔒 Modern | Symmetric | Mobile/ARM devices, software-only |
| `fernet` | 🔒 Modern | Symmetric | Simple password-based encryption |
| `rsa-oaep` | 🔒 Modern | Asymmetric | Key exchange, small data (<190 bytes) |
| `hybrid-rsa-aes` | 🔒 Modern | Hybrid | Large files with asymmetric keys |
| `caesar` | ⚠️ Classical | Substitution | Educational only |
| `vigenere` | ⚠️ Classical | Polyalphabetic | Educational only |
| `playfair` | ⚠️ Classical | Digraph | Educational only |
| `morse` | ⚠️ Encoding | Encoding | Text encoding, educational |

> ⚠️ **Warning:** Classical ciphers (Caesar, Vigenère, Playfair) are cryptographically broken and provided for educational purposes only. Do not use for sensitive data.

---

## 💡 Examples

### Encrypt with Different Ciphers

```bash
# AES-256-GCM (default)
pylock encrypt secrets.txt

# ChaCha20-Poly1305 (better for mobile)
pylock encrypt mobile-data.zip -c chacha20

# RSA (for small files or key wrapping)
pylock encrypt api-key.txt -c rsa-oaep

# Hybrid (RSA + AES for large files)
pylock encrypt database.sql -c hybrid-rsa-aes
```

### Batch Encryption

```bash
# Encrypt entire folder
pylock encrypt ~/Documents/Private --cipher aes-256-gcm -o private.enc

# Decrypt folder
pylock decrypt private.enc -o ~/Documents/Private
```

### Key Management

```bash
# Generate and save key
pylock generate-key -c aes-256-gcm -o master.key

# Encrypt with saved key
pylock encrypt file.txt --key-file master.key

# Decrypt with same key
pylock decrypt file.txt.locked --key-file master.key
```

### Brute Force (Recovery)

```bash
# Attempt password recovery
pylock decrypt unknown.locked --brute-force --wordlist passwords.txt
```

---

## 🏗️ Architecture

```
PyLock/
├── pylock/
│   ├── cli.py              # Click + Rich interface
│   ├── core/
│   │   ├── pylock.py       # Core encryption engine
│   │   ├── lock.py         # Process lock manager
│   │   └── exceptions.py   # Custom exceptions
│   ├── ciphers/
│   │   ├── aes256gsm.py    # AES-256-GCM implementation
│   │   ├── chacha20.py     # ChaCha20-Poly1305
│   │   ├── rsa.py          # RSA-OAEP
│   │   ├── hybridrsa_aes.py # Hybrid encryption
│   │   ├── classical.py    # Caesar, Vigenère, Playfair
│   │   └── factory.py      # Cipher factory
│   └── utils/
│       ├── logging.py      # Rich logging
│       └── file_utils.py   # File operations
```

---

## ⚠️ Security Notice

**PyLock is designed for legitimate data protection. Please use responsibly:**

- 🔑 **Keep passwords safe** — Lost passwords cannot be recovered (unless brute force succeeds)
- 🗝️ **Backup encryption keys** — Store key files in secure, separate locations
- 🧪 **Test decryption** — Always verify you can decrypt before deleting originals
- 📋 **Use strong passwords** — Combine uppercase, lowercase, numbers, and symbols
- 🏛️ **Compliance** — Ensure your use complies with local laws and regulations

> **Warning:** Irresponsible use can result in permanent data loss. The authors are not responsible for lost data due to forgotten passwords or corrupted key files.

---

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Fork and clone
git clone https://github.com/your-username/pylock.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests
isort src tests

# Type check
mypy src/pylock
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [Click](https://click.palletsprojects.com/) — Command line interface framework
- [Rich](https://rich.readthedocs.io/) — Beautiful terminal formatting
- [Cryptography](https://cryptography.io/) — Modern cryptographic recipes
- [PyCryptodome](https://www.pycryptodome.org/) — Low-level cryptographic primitives
- [Shields.io](https://shields.io/) — Status badges

---

<div align="center">

Made with ❤️ by **Wambua (Skye-Cyber)**

⭐ Star us on GitHub — it motivates us to keep improving!

</div>
