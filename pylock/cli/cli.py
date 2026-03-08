import os
import sys
from pathlib import Path
import click
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from typing import Optional
from rich.prompt import Prompt
from rich import box
from ..core.pylockmanager import PyLock
from ..ciphers.factory import CipherFactory
from .__shared__ import console  # , STYLES
from .utils import print_ciphers_table, print_banner
from ..utils.file_utils import FileSystemHandler


# Custom Click context for sharing state
class Context:
    def __init__(self):
        self.pylock = PyLock()
        self.fs = FileSystemHandler()
        self.verbose = False
        self.quiet = False


pass_context = click.make_pass_decorator(Context, ensure=True)


# Main CLI Group
@click.group(invoke_without_command=True)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-error output")
@click.version_option(version="1.0.0", prog_name="pylock")
@pass_context
def cli(ctx, verbose, quiet):
    """
    🔐 PyLock - Modern File Encryption Tool

    Encrypt and decrypt files and folders using various ciphers.
    Run [bold cyan]pylock COMMAND --help[/bold cyan] for command-specific options.
    """
    ctx.verbose = verbose
    ctx.quiet = quiet

    if not ctx.quiet and not sys.argv[1:]:
        print_banner()
        console.print("[dim]Run [bold]pylock --help[/bold] for usage information[/dim]")
        console.print()


# Encrypt Command
@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-c",
    "--cipher",
    type=click.Choice(list(CipherFactory.CIPHERS.keys()), case_sensitive=False),
    default="aes-256-gcm",
    help="Encryption cipher to use (default: aes-256-gcm)",
)
@click.option(
    "-p",
    "--passphrase",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="Encryption passphrase (will be prompted if not provided)",
)
@click.option(
    "-k",
    "--key-file",
    type=click.Path(path_type=Path),
    help="Save encryption key to file",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Output file/directory (default: in-place with .locked suffix)",
)
@click.option(
    "--no-compress",
    is_flag=True,
    help="Disable compression before encryption",
)
@pass_context
def encrypt(ctx, path, cipher, passphrase, key_file, output, no_compress):
    """
    🔒 Encrypt a file or folder.

    PATH: File or directory to encrypt

    \b
    Examples:
        pylock encrypt secret.txt
        pylock encrypt documents/ -c chacha20 -p mypassword
        pylock encrypt data.zip -o encrypted.data
    """
    if not ctx.quiet:
        console.print(
            f"\n[bold cyan]🔒 Encrypting:[/bold cyan] [highlight]{path}[/highlight]"
        )
        console.print(f"[dim]Cipher:[/dim] {cipher.upper()}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=ctx.quiet,
        ) as progress:
            task = progress.add_task(description="Initializing...", total=None)

            # Validate cipher compatibility
            cipher_obj = CipherFactory.create(cipher)

            progress.update(task, description="Checking data compatibility...")
            if not cipher_obj.is_data_compatible("test"):
                console.print(f"[error]Cipher {cipher} not available[/error]")
                raise click.Abort()

            # Perform encryption
            progress.update(task, description="Encrypting data...")
            if path.is_dir():
                files = ctx.fs.collect_files(path.expanduser().absolute())
                result = [path, len(files)]
                try:
                    progress.columns = [
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        TimeRemainingColumn(),
                    ]
                    encrypt_task = progress.add_task(
                        description="", start=1, total=len(files)
                    )
                    for file in files:
                        try:
                            ctx.pylock.encrypt_file(
                                path=Path(file),
                                passphrase=passphrase,
                                cipher=cipher,
                                compress=not no_compress,
                                output_path=output,
                            )
                            progress.update(task_id=encrypt_task, advance=1)
                            os.unlink(Path(file).absolute().as_posix())
                        except Exception:
                            continue
                    # Reset to spinner
                    progress.update(encrypt_task, completed=len(files))
                    progress.columns = [
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                    ]
                    # result = ctx.pylock.encrypt_directory(
                    #     path=path,
                    #     passphrase=passphrase,
                    #     cipher=cipher,
                    #     compress=not no_compress,
                    #     output_path=output,
                    # )
                except Exception:
                    if ctx.verbose:
                        console.print_exception()
            else:
                result = ctx.pylock.encrypt_file(
                    path=path,
                    passphrase=passphrase,
                    cipher=cipher,
                    compress=not no_compress,
                    output_path=output,
                )
                try:
                    os.unlink(path.absolute().as_posix())
                except Exception:
                    pass

            progress.update(task, description="Finalizing...")

            # Save key if requested
            if key_file:
                progress.update(task, description="Saving key file...")
                ctx.pylock.save_key_file(key_file, passphrase)

        if not ctx.quiet:
            output_path = result[0]
            console.print("\n[success]✓ Encryption successful![/success]")
            console.print(f"[dim]Output:[/dim] [highlight]{output_path}[/highlight]")

            # Show security info
            info_table = Table(box=box.SIMPLE, show_header=False)
            info_table.add_row("Cipher", cipher.upper())
            if path.is_file():
                info_table.add_row(
                    "File size:",
                    f"{os.path.getsize(Path(output_path).absolute().as_posix()):,} bytes",
                )
            info_table.add_row(
                "File count:",
                f"{result[1]} {'files' if result[1] > 1 else 'file'}",
            )
            if key_file:
                info_table.add_row("Key file", str(key_file))
            console.print(
                Panel(
                    info_table,
                    title="[bold]Details[/bold]",
                    border_style="green",
                    expand=False,
                )
            )

    except Exception as e:
        console.print(f"\n[error]✗ Encryption failed:[/error] {str(e)}")
        if ctx.verbose:
            console.print_exception()
        raise click.Abort()


# Decrypt Command
@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-p",
    "--passphrase",
    prompt=True,
    hide_input=True,
    help="Decryption passphrase (will be prompted if not provided)",
)
@click.option(
    "-c",
    "--cipher",
    type=click.Choice(list(CipherFactory.CIPHERS.keys()), case_sensitive=False),
    default="aes-256-gcm",
    help="Encryption cipher to use (default: aes-256-gcm), System shall attempt detection",
)
@click.option(
    "-k",
    "--key-file",
    type=click.Path(exists=True, path_type=Path),
    help="Read decryption key from file",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Output file/directory (default: remove .locked suffix)",
)
@click.option(
    "--brute-force",
    "-b",
    is_flag=True,
    help="Attempt brute force with wordlist",
)
@click.option(
    "--wordlist",
    "-w",
    type=click.Path(exists=True, path_type=Path),
    help="Wordlist file for brute force",
)
@pass_context
def decrypt(ctx, path, passphrase, cipher, key_file, output, brute_force, wordlist):
    """
    🔓 Decrypt a file or folder.

    PATH: File or directory to decrypt (.locked extension recommended)

    \b
    Examples:
        pylock decrypt secret.txt.locked
        pylock decrypt encrypted.data -p mypassword -o decrypted.txt
        pylock decrypt data.zip.locked --brute-force -w passwords.txt
    """
    if not ctx.quiet:
        console.print(
            f"\n[bold cyan]🔓 Decrypting:[/bold cyan] [highlight]{path}[/highlight]"
        )

    try:
        # Load key from file if provided
        if key_file:
            password = ctx.pylock.load_key_file(key_file)

        if brute_force and wordlist:
            console.print("[warning]⚠ Brute force mode enabled[/warning]")
            password = _brute_force_decrypt(ctx, path, wordlist)
            if not password:
                console.print(
                    "[error]✗ Brute force failed - password not found[/error]"
                )
                raise click.Abort()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=ctx.quiet,
        ) as progress:
            task = progress.add_task(description="Initializing...", total=None)

            progress.update(task, description="Decrypting data...")

            if path.is_dir():
                files = ctx.fs.collect_files(path.expanduser().absolute())
                result = [path, len(files)]
                try:
                    progress.columns = [
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        TimeRemainingColumn(),
                    ]
                    decrypt_task = progress.add_task(
                        description="", start=1, total=len(files)
                    )
                    for file in files:
                        try:
                            ctx.pylock.decrypt_file(
                                path=Path(file),
                                passphrase=passphrase,
                                cipher=cipher,
                                output_path=output,
                            )
                            progress.advance(task_id=decrypt_task, advance=1)
                            os.unlink(Path(file).absolute().as_posix())
                        except Exception:
                            continue

                    progress.update(decrypt_task, completed=len(files))
                    # Reset progress columns to SpinnerColumn
                    progress.columns = [
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                    ]
                    # result = ctx.pylock.decrypt_directory(
                    #     path=path,
                    #     passphrase=passphrase,
                    #     cipher=cipher,
                    #     output_path=output,
                    # )
                except Exception:
                    if ctx.verbose:
                        console.print_exception()
            else:
                result = ctx.pylock.decrypt_file(
                    path=path,
                    passphrase=passphrase,
                    cipher=cipher,
                    output_path=output,
                )
                try:
                    os.unlink(path.absolute().as_posix())
                except Exception:
                    pass

            progress.update(task, description="Verifying integrity...")

        if not ctx.quiet:
            output_path = result[0]
            console.print("\n[success]✓ Decryption successful![/success]")
            console.print(f"[dim]Output:[/dim] [highlight]{output_path}[/highlight]")

            info_table = Table(box=box.SIMPLE, show_header=False)
            if path.is_file():
                info_table.add_row(
                    "File size:",
                    f"{os.path.getsize(Path(output_path).absolute().as_posix()):,} bytes",
                )
            info_table.add_row(
                "File count:",
                f"{result[1]} {'files' if result[1] > 1 else 'file'}",
            )
            console.print(
                Panel(
                    info_table,
                    title="[bold]Details[/bold]",
                    border_style="green",
                    expand=False,
                )
            )
    except Exception as e:
        console.print(f"\n[error]✗ Decryption failed:[/error] {str(e)}")
        if "Invalid passphrase" in str(e) or "decryption failed" in str(e).lower():
            console.print(
                "[warning]Hint: Verify your passphrase or try a different cipher[/warning]"
            )
        if ctx.verbose:
            console.print_exception()
        raise click.Abort()


# List Ciphers Command
@cli.command(name="list-ciphers")
def list_ciphers():
    """
    📋 Display available encryption ciphers and their properties.
    """
    print_banner()
    print_ciphers_table()


# Generate Key Command
@cli.command()
@click.option(
    "-c",
    "--cipher",
    type=click.Choice(["aes-256-gcm", "chacha20", "fernet", "rsa"]),
    default="aes-256-gcm",
    help="Cipher type for key generation",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    required=True,
    help="Output file for the generated key",
)
@click.option(
    "--no-password",
    is_flag=True,
    help="Do not encrypt the key file with a password",
)
@pass_context
def generate_key(ctx, cipher, output, no_password):
    """
    🔑 Generate a new encryption key.

    Useful for asymmetric ciphers (RSA) or creating secure random keys.
    """
    if not ctx.quiet:
        console.print(f"\n[bold cyan]🔑 Generating {cipher.upper()} key...[/bold cyan]")

    try:
        key_password = None
        if not no_password and cipher in ["aes-256-gcm", "chacha20", "fernet"]:
            key_password = Prompt.ask(
                "Enter password to protect key file", password=True
            )

        ctx.pylock.generate_key(cipher, output, password=key_password)

        if not ctx.quiet:
            console.print(
                f"\n[success]✓ Key saved to:[/success] [highlight]{output}[/highlight]"
            )
            console.print(
                f"[dim]Permissions:[/dim] {oct(os.stat(output).st_mode)[-3:]}"
            )

    except Exception as e:
        console.print(f"\n[error]✗ Key generation failed:[/error] {str(e)}")
        raise click.Abort()


# Verify Command
@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@pass_context
def verify(ctx, path):
    """
    ✓ Verify if a file is encrypted and show metadata.
    """
    if not ctx.quiet:
        console.print(
            f"\n[bold cyan]🔍 Analyzing:[/bold cyan] [highlight]{path}[/highlight]"
        )

    try:
        info = ctx.pylock.read_encryption_info(path)

        if not info:
            console.print("[warning]⚠ File does not appear to be encrypted[/warning]")
            return

        # Display info in a nice table
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="white")

        for key, value in info.items():
            if key == "is_encrypted":
                continue
            table.add_row(key.replace("_", " ").title(), str(value))

        console.print(
            Panel(table, title="[bold]Encryption Metadata[/bold]", border_style="green")
        )

    except Exception as e:
        console.print(f"\n[error]✗ Verification failed:[/error] {str(e)}")
        raise click.Abort()


# Interactive Mode
@cli.command()
@pass_context
def interactive(ctx):
    """
    🖥️  Launch interactive mode with guided prompts.
    """
    print_banner()
    console.print("[bold]Interactive Mode[/bold] - Follow the prompts\n")

    action = Prompt.ask(
        "Choose action",
        choices=["encrypt", "decrypt", "generate-key", "exit"],
        default="encrypt",
    )

    if action == "exit":
        console.print("[dim]Goodbye![/dim]")
        return

    if action == "generate-key":
        cipher = Prompt.ask("Cipher", choices=list(CipherFactory.CIPHERS.keys()))
        output = Path(Prompt.ask("Output file path"))
        ctx.invoke(generate_key, cipher=cipher, output=output, no_password=False)
        return

    # Encrypt or Decrypt
    path = Path(Prompt.ask("File or folder path"))

    if not path.exists():
        console.print(f"[error]Path not found: {path}[/error]")
        return

    if action == "encrypt":
        cipher = Prompt.ask(
            "Cipher", choices=list(CipherFactory.CIPHERS.keys()), default="aes-256-gcm"
        )
        password = Prompt.ask("Password", password=True)
        confirm = Prompt.ask("Confirm password", password=True)

        if password != confirm:
            console.print("[error]Passwords do not match![/error]")
            return

        output = Prompt.ask("Output path (optional)", default="")
        output = Path(output) if output else None

        ctx.invoke(
            encrypt,
            path=path,
            cipher=cipher,
            password=password,
            output=output,
            key_file=None,
            no_compress=False,
        )

    else:  # decrypt
        password = Prompt.ask("Password", password=True)
        output = Prompt.ask("Output path (optional)", default="")
        output = Path(output) if output else None

        ctx.invoke(
            decrypt,
            path=path,
            password=password,
            output=output,
            key_file=None,
            brute_force=False,
            wordlist=None,
        )


# Helper function for brute force
def _brute_force_decrypt(ctx, path: Path, wordlist: Path) -> Optional[str]:
    """Attempt to decrypt using wordlist."""
    passwords = wordlist.read_text().splitlines()

    console.print(f"[dim]Loaded {len(passwords)} passwords to try...[/dim]")

    with Progress(
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        "{task.completed}/{task.total}",
        console=console,
    ) as progress:
        task = progress.add_task("Brute forcing...", total=len(passwords))

        for pwd in passwords:
            progress.update(task, advance=1)
            try:
                # Quick test decryption
                ctx.pylock.test_decrypt(path, pwd)
                console.print("[success]✓ Password found![/success]")
                return pwd
            except Exception:
                continue

    return None


# Main entry point
def main():
    """Entry point for the CLI application."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[warning]⚠ Interrupted by user[/warning]")
        sys.exit(1)
    except click.Abort:
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[error]Fatal error:[/error] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
