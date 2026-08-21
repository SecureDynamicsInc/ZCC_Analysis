"""Entry point: ``python -m zcc_diag <bundle.zip>``."""
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
