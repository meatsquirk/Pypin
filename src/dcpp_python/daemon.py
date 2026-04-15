"""Compatibility shim for dcpp_python.node.daemon."""

import sys

from dcpp_python.node.daemon import *  # noqa: F401,F403
from dcpp_python.node.daemon import _get_bt_backend_from_env, main  # noqa: F401


if __name__ == "__main__":
    sys.exit(main())
