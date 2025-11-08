"""depurls package

Public API:
- __version__ : current package version
- main        : console entry point function

Typical usage:
	from depurls import main
	main()  # equivalent to running `depurls` CLI
"""

__version__ = "0.1.0"

from .main import main, parse_args  # re-export for convenience

__all__ = ["__version__", "main", "parse_args"]
