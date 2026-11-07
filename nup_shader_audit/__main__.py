"""Enable python -m nup_shader_audit."""

from .cli import main

# Guarded: spawned worker processes import this module and must not run the CLI again.
if __name__ == "__main__":
    raise SystemExit(main())
