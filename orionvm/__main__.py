"""Allow `python -m orionvm` to invoke the CLI."""
from .cli import main
import sys

sys.exit(main())
