from rich import box
from rich.table import Table
from .__shared__ import console
from .banner import banner


def print_banner():
    """Display application banner."""
    console.print(banner)


def print_ciphers_table():
    """Display available ciphers in a formatted table."""
    table = Table(
        title="[bold]Available Encryption Ciphers[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Cipher", style="bold green")
    table.add_column("Security", style="yellow")
    table.add_column("Use Case", style="dim white")
    table.add_column("Password", style="cyan")

    ciphers_info = [
        ("AES-256-GCM", "🔒 Modern", "General purpose encryption", "✓ Required"),
        ("ChaCha20-Poly1305", "🔒 Modern", "Mobile/ARM devices", "✓ Required"),
        ("Fernet", "🔒 Modern", "Simple password-based", "✓ Required"),
        ("RSA-OAEP", "🔒 Asymmetric", "Key exchange, small data", "Key pair"),
        ("Hybrid-RSA-AES", "🔒 Modern", "Large data + asymmetric", "Key pair"),
        ("Caesar", "⚠️  Classical", "Educational only", "✗ Shift number"),
        ("Vigenère", "⚠️  Classical", "Educational only", "Keyword"),
        ("Playfair", "⚠️  Classical", "Educational only", "Keyword"),
        # ("Morse", "⚠️  Encoding", "Text encoding", "✗ None"),
    ]

    for cipher, security, use_case, password in ciphers_info:
        table.add_row(cipher, security, use_case, password)

    console.print(table)
    console.print(
        "\n[dim]Note: Classical ciphers are for educational purposes only. "
        "Do not use for sensitive data.[/dim]\n"
    )
