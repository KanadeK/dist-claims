# Contributing

Discuss a reproducible bug or scoped feature in an issue before a large change.
Use synthetic fixtures, never credentials or private input. Python 3.11+ is required.

```sh
python -m unittest discover -s tests -v
python -m pip install ruff==0.17.2 build==1.6.1
python -m ruff check .
python -m ruff format --check .
python -m build
```

Include a regression that demonstrates the user-visible failure. Keep runtime
dependencies empty unless a concrete requirement warrants changing that policy.
The maintainer reviews proposals and retains control over published commits;
CI runs checks only and never commits, merges, or updates source automatically.
