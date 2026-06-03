#!/usr/bin/env python3
"""
BugBounty Hunter - Installer
Checks Python version, optionally creates a venv, and installs dependencies.
Works on Windows, macOS, and Linux.
"""

import os
import sys
import subprocess
import platform


# ── Colours ───────────────────────────────────────────────────────────────────

def supports_colour():
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOUR = supports_colour()

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def info(msg):    print(c(f"  [*] {msg}", "96"))
def success(msg): print(c(f"  [+] {msg}", "92"))
def warn(msg):    print(c(f"  [!] {msg}", "93"))
def error(msg):   print(c(f"  [x] {msg}", "91"))
def header(msg):  print(c(f"\n{msg}", "1;96"))
def rule():       print(c("  " + "-" * 54, "90"))


# ── Core helpers ──────────────────────────────────────────────────────────────

def run_cmd(args, check=True, capture=False):
    """Run a subprocess command given as a flat list of strings."""
    # Safety check: every element must be a plain string
    flat = []
    for item in args:
        if isinstance(item, list):
            flat.extend(item)
        else:
            flat.append(str(item))
    return subprocess.run(flat, check=check, capture_output=capture, text=True)


def get_pip(venv_dir=None):
    """
    Return a flat list suitable for use as the start of a pip command.
    e.g.  ["venv\\Scripts\\pip.exe"]
    or    ["C:\\Python314\\python.exe", "-m", "pip"]
    """
    if venv_dir:
        if platform.system() == "Windows":
            exe = os.path.join(venv_dir, "Scripts", "pip.exe")
        else:
            exe = os.path.join(venv_dir, "bin", "pip")
        return [exe]
    # Fallback: invoke pip as a module through the current interpreter
    return [sys.executable, "-m", "pip"]


def get_python(venv_dir):
    """Return path to the python executable inside a venv."""
    if platform.system() == "Windows":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def activate_hint(venv_dir):
    if platform.system() == "Windows":
        bat = os.path.join(venv_dir, "Scripts", "activate.bat")
        ps1 = os.path.join(venv_dir, "Scripts", "Activate.ps1")
        print(c("\n  To activate the virtual environment:", "93"))
        print(c(f"    Command Prompt : {bat}", "97"))
        print(c(f"    PowerShell     : {ps1}", "97"))
    else:
        print(c(f"\n  To activate the virtual environment:", "93"))
        print(c(f"    source {venv_dir}/bin/activate", "97"))


# ── Steps ─────────────────────────────────────────────────────────────────────

def check_python():
    header("Step 1 - Checking Python version")
    rule()
    major, minor = sys.version_info[:2]
    info(f"Found Python {major}.{minor} ({platform.system()})")
    if (major, minor) < (3, 10):
        error(f"Python 3.10+ is required (you have {major}.{minor}).")
        print(c("  Download from: https://www.python.org/downloads/", "97"))
        sys.exit(1)
    success(f"Python {major}.{minor} - OK")


def create_venv(venv_dir):
    header("Step 2 - Creating virtual environment")
    rule()
    if os.path.isdir(venv_dir):
        warn(f"Virtual environment '{venv_dir}' already exists - skipping.")
        return
    info(f"Creating venv at: {os.path.abspath(venv_dir)}")
    try:
        run_cmd([sys.executable, "-m", "venv", venv_dir])
        success(f"Virtual environment created at '{venv_dir}'")
    except subprocess.CalledProcessError:
        error("Failed to create virtual environment.")
        info("Re-run with --no-venv to install into system Python instead.")
        sys.exit(1)


def install_deps(pip_cmd, requirements="requirements.txt"):
    """
    pip_cmd is a flat list of strings, e.g. ["venv\\Scripts\\pip.exe"]
    or ["python.exe", "-m", "pip"].
    """
    header("Step 3 - Installing dependencies")
    rule()

    if not os.path.isfile(requirements):
        error(f"'{requirements}' not found.")
        info("Make sure you are running this script from the bugbounty-hunter folder.")
        sys.exit(1)

    info(f"pip command : {' '.join(pip_cmd)}")
    info(f"requirements: {requirements}")
    print()

    def attempt(extra_flags):
        run_cmd(pip_cmd + ["install", "--upgrade", "pip", "-q"] + extra_flags)
        run_cmd(pip_cmd + ["install", "-r", requirements] + extra_flags)

    try:
        attempt([])
        print()
        success("All dependencies installed.")
        return
    except subprocess.CalledProcessError:
        pass

    # Debian/Ubuntu "externally managed" environments need this flag
    warn("Retrying with --break-system-packages (Debian/Ubuntu systems)...")
    try:
        attempt(["--break-system-packages"])
        print()
        success("All dependencies installed.")
    except subprocess.CalledProcessError:
        error("pip install failed.")
        info(f"Try manually: {' '.join(pip_cmd)} install -r {requirements}")
        sys.exit(1)


def verify(pip_cmd):
    header("Step 4 - Verifying installation")
    rule()

    packages = [
        ("requests",  "requests"),
        ("bs4",       "beautifulsoup4"),
        ("lxml",      "lxml"),
        ("urllib3",   "urllib3"),
    ]

    all_ok = True
    for label, pkg in packages:
        result = run_cmd(pip_cmd + ["show", pkg], check=False, capture=True)
        if result.returncode == 0:
            version = next(
                (ln.split(":", 1)[1].strip()
                 for ln in result.stdout.splitlines()
                 if ln.startswith("Version")),
                "unknown",
            )
            success(f"{label:<20} {version}")
        else:
            error(f"{label:<20} NOT FOUND")
            all_ok = False

    if not all_ok:
        warn("Some packages are missing - try running the installer again.")
        sys.exit(1)


def print_summary(venv_dir, use_venv):
    header("Done!")
    rule()
    success("BugBounty Hunter is ready.\n")
    if use_venv:
        activate_hint(venv_dir)
        py = get_python(venv_dir)
    else:
        py = sys.executable
    print(c("\n  Run a scan:", "93"))
    print(c(f"    {py} main.py --target https://example.com\n", "97"))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print(c("""
  +========================================================+
  |         BugBounty Hunter - Installer                   |
  +========================================================+""", "1;96"))

    use_venv = "--no-venv" not in sys.argv
    venv_dir = "venv"

    check_python()

    if use_venv:
        create_venv(venv_dir)
        pip_cmd = get_pip(venv_dir)   # e.g. ["venv\\Scripts\\pip.exe"]
    else:
        warn("Skipping virtual environment - installing into system Python.")
        pip_cmd = get_pip()           # e.g. ["python.exe", "-m", "pip"]

    # Confirm pip_cmd is a flat list of strings before doing anything with it
    assert all(isinstance(x, str) for x in pip_cmd), f"pip_cmd must be strings: {pip_cmd}"

    install_deps(pip_cmd)
    verify(pip_cmd)
    print_summary(venv_dir, use_venv)


if __name__ == "__main__":
    main()
