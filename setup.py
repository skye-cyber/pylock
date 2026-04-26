#!/usr/bin/env python3
"""Setup configuration for PyLock encryption suite."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

# Read requirements
REQUIREMENTS = [
    "click>=8.1.0",
    "rich>=13.0.0",
    "cryptography>=41.0.0",
    "pycryptodome>=3.19.0",
    "psutil>=5.9.0",  # For lock manager process checking
]

DESCRIPTION = (
    "Modern CLI tool for encrypting and decrypting files and folders with style"
)

setup(
    name="pylock",
    version="2.0.0",
    author="Wambua (Skye-Cyber)",
    author_email="swskye17@gmail.com",
    description=DESCRIPTION,
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/skye-cyber/pylock",
    packages=find_packages(exclude=["tests", "docs", "build", "dist"]),
    package_dir={"": ""},
    python_requires=">=3.8",
    install_requires=REQUIREMENTS,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pylock=pylock.cli:main",
            "pl=pylock.cli:main",  # Short alias
        ],
    },
    include_package_data=True,
    zip_safe=False,
    license="GPL-3.0-or-later",
    keywords=[
        "pylock",
        "encryption",
        "decryption",
        "file-encryption",
        "folder-encryption",
        "cryptography",
        "aes",
        "chacha20",
        "rsa",
        "cli",
        "security",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        # "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
        "Typing :: Typed",
    ],
    project_urls={
        "Bug Reports": "https://github.com/skye-cyber/PyLock/issues",
        "Source": "https://github.com/skye-cyber/PyLock",
        "Documentation": "https://github.com/skye-cyber/PyLock/wiki",
    },
)
