#!/usr/bin/env python3
"""
CLI entry point for ``bugbounty-hunter``.

Primary interface::

    bugbounty-hunter scan https://target.com [options]

Also supports the traditional::

    python3 main.py --target https://target.com [options]

Both routes through the same code path.
"""

import sys


def main() -> int:
    """Entry point for ``bugbounty-hunter scan URL`` console_scripts.

    Delegates to ``main.main()`` so both entry points share the same
    implementation.
    """
    from main import main as _main
    return _main()


if __name__ == "__main__":
    sys.exit(main())
