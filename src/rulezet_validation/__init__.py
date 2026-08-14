"""Mirror rulezet.org's YARA rules and validate them against known-clean binaries.

Two halves that share a directory layout and nothing else:

* **mirror** -- fetch ~130k rules, tag them in Rulezet's own MISP-style
  vocabulary, compile them, and gate them against a clean-binary baseline.
* **validate** -- judge rules on their own merits, with no mirror involved.

The gate's criterion is deliberately narrow: a rule is quarantined if and only
if it fired on the baseline. See `gate` for why nothing else is allowed to move
a file.
"""

__version__ = "0.1.0"

# Nothing else is re-exported here on purpose. `gate.gate` and `sync.sync` are
# the natural names for those functions, and lifting them to the package would
# shadow the modules they live in -- `from rulezet_validation import gate` would
# hand you a function. Import from the module: `from rulezet_validation.gate
# import gate`.
from .config import load as load_config  # noqa: F401
from .config import paths  # noqa: F401
