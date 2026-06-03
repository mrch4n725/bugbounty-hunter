#!/usr/bin/env python3
"""
BugBounty Hunter — installer
Checks Python version, optionally creates a venv, and installs dependencies.
Works on Windows, macOS, and Linux.
"""

import os
import sys
import subprocess
import platform


# ── Colours (disabled on Windows unless ANSI is supported) ───────────────────

def supports_colour():
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOUR = supports_colour()

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def info(msg):    print(c(f"  [*] {msg}", "96"))
def success(msg): print(c(f"  [✓] {msg}", "92"))
def warn(msg):    print(c(f"  [!] {msg}", "93"))
def error(msg):   print(c(f"  [✗] {msg}", "91"))
def header(msg):  print(c(f"\n{msg}", "1;96"))
def rule():       print(c("  " + "─" * 54, "90"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, check=True, capture=False):
    """Run a command, return CompletedProcess."""
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
    )


def pip_path(venv_dir=None):
    """Return the pip executable path, inside venv if given."""
    if venv_dir:
        if platform.system() == "Windows":
            return os.path.join(venv_dir, "Scripts", "pip.exe")
        return os.path.join(venv_dir, "bin", "pip")
    return sys.executable.replace("python", "pip")   # fallback


def python_path(venv_dir):
    """Return the python executable inside a venv."""
    if platform.system() == "Windows":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def activate_hint(venv_dir):
    """Print platform-appropriate activation instructions."""
    if platform.system() == "Windows":
        cmd   = os.path.join(venv_dir, "Scripts", "activate.bat")
        ps1   = os.path.join(venv_dir, "Scripts", "Activate.ps1")
        print(c(f"\n  To activate the virtual environment:", "93"))
        print(c(f"    Command Prompt : {cmd}", "97"))
        print(c(f"    PowerShell     : {ps1}", "97"))
    else:
        print(c(f"\n  To activate the virtual environment:", "93"))
        print(c(f"    source {venv_dir}/bin/activate", "97"))


# ── Steps ─────────────────────────────────────────────────────────────────────

def check_python():
    header("Step 1 — Checking Python version")
    rule()
    major, minor = sys.version_info[:2]
    info(f"Found Python {major}.{minor} ({platform.system()})")

    if (major, minor) < (3, 10):
        error(f"Python 3.10+ is required (you have {major}.{minor}).")
        print(c("\n  Download the latest Python from: https://www.python.org/downloads/", "97"))
        sys.exit(1)

    success(f"Python {major}.{minor} — OK")


def create_venv(venv_dir):
    header("Step 2 — Creating virtual environment")
    rule()

    if os.path.isdir(venv_dir):
        warn(f"Virtual environment '{venv_dir}' already exists — skipping creation.")
        return

    info(f"Creating venv at: {os.path.abspath(venv_dir)}")
    try:
        run([sys.executable, "-m", "venv", venv_dir])
        success(f"Virtual environment created at '{venv_dir}'")
    except subprocess.CalledProcessError:
        error("Failed to create virtual environment.")
        info("You can install globally by re-running with:  python install.py --no-venv")
        sys.exit(1)


def install_deps(pip_exe, requirements="requirements.txt"):
    header("Step 3 — Installing dependencies")
    rule()

    if not os.path.isfile(requirements):
        error(f"'{requirements}' not found. Are you in the bugbounty-hunter directory?")
        sys.exit(1)

    info(f"Running: {pip_exe} install -r {requirements}")
    print()
    try:
        run([pip_exe, "install", "--upgrade", "pip", "-q"])
        run([pip_exe, "install", "-r", requirements])
        print()
        success("All dependencies installed successfully.")
    except subprocess.CalledProcessError:
        error("pip install failed.")
        info("Try running manually:  pip install -r requirements.txt")
        sys.exit(1)


def verify(pip_exe):
    header("Step 4 — Verifying installation")
    rule()

    packages = ["requests", "bs4", "lxml", "urllib3"]
    all_ok = True
    for pkg in packages:
        result = run([pip_exe, "show", pkg], check=False, capture=True)
        if result.returncode == 0:
            # Extract version from output
            version = next(
                (line.split(":", 1)[1].strip() for line in result.stdout.splitlines() if line.startswith("Version")),
                "unknown"
            )
            success(f"{pkg:<20} {version}")
        else:
            error(f"{pkg:<20} NOT FOUND")
            all_ok = False

    if not all_ok:
        warn("Some packages are missing — try running install again.")
        sys.exit(1)


def print_summary(venv_dir, use_venv):
    header("Done!")
    rule()
    success("BugBounty Hunter is ready to use.\n")

    if use_venv:
        activate_hint(venv_dir)
        py = python_path(venv_dir)
    else:
        py = "python"

    print(c("\n  Run a scan:", "93"))
    print(c(f"    {py} main.py --target https://example.com\n", "97"))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(c("""
  ╔══════════════════════════════════════════════════════╗
  ║          BugBounty Hunter — Installer                ║
  ╚══════════════════════════════════════════════════════╝""", "1;96"))

    use_venv = "--no-venv" not in sys.argv
    venv_dir = "venv"

    check_python()

    if use_venv:
        create_venv(venv_dir)
        pip_exe = pip_path(venv_dir)
    else:
        warn("Skipping virtual environment — installing into system Python.")
        pip_exe = [sys.executable, "-m", "pip"]
        # Flatten to string for run() calls below
        pip_exe = sys.executable + " -m pip"
        pip_exe = [sys.executable, "-m", "pip"]

    # Normalise pip_exe to always be a list
    if isinstance(pip_exe, str):
        pip_exe = pip_exe.split()

    install_deps(pip_exe)
    verify(pip_exe)
    print_summary(venv_dir, use_venv)


if __name__ == "__main__":
    main()
