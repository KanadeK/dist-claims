# Release verification

For version 0.1.0, local Windows/Python 3.13.16 verification ran 28 unittest
cases successfully, with one skipped because Windows did not permit creating a
symbolic link. Linux/macOS CI exercises that test where symlinks are supported.
Ruff 0.17.2 lint and formatting checks passed. Both wheel and source distribution
built successfully using build 1.6.1 and setuptools 84.2.1.

A fresh disposable virtual environment installed the wheel with `--no-index
--no-deps`, from outside the checkout. The installed command first reported a
clean environment. Two original synthetic wheels were then installed with a
shared module and command; the installed tool reported both conflicts and
different recorded SHA-256 hashes, with exit 1 and complete coverage. Uninstalling
one demonstration distribution removed the shared module while leaving the
other distribution's metadata, reproducing the failure this diagnostic targets.
The tool was uninstalled and the disposable environment removed.

The test suite includes malformed/missing/oversized metadata, total byte and
count budgets, CSV quoting, duplicate names, case matching, entry-point collisions,
legacy coverage, no package imports, and actual CLI exit codes. These are
synthetic controlled cases, not a claim of exhaustive real-world compatibility.

CI results are public under the repository's Actions tab. A configured workflow
is not itself proof of a passing run. No large-environment benchmark or adversarial
concurrent filesystem mutation test has been performed.
