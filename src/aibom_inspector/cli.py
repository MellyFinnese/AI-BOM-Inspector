from __future__ import annotations

from .cli_shim import main
from .product_commands import register_commands

register_commands(main)


if __name__ == "__main__":
    main()
