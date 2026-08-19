.PHONY: build check doctor format lint refresh-build-constraints scan-staged security sync test typecheck verifier-coverage verify-artifacts

sync:
	uv sync --locked --all-groups --all-packages

scan-staged:
	env -u SKIP -u CAIRNVM_GITLEAKS_BOOTSTRAPPED CAIRNVM_SECRET_SCAN_SCOPE=staged uv run --locked --all-packages python scripts/verify_secret_scanner.py

format:
	uv run --locked --all-packages python -m ruff format .

lint:
	uv run --locked --all-packages python -m ruff check .
	uv run --locked --all-packages python -m ruff format --check .

typecheck:
	uv run --locked --all-packages python -m mypy

test:
	uv run --locked --all-packages python -m pytest

security:
	uv run --locked --all-groups --all-packages python -m pip_audit

build:
	uv build --all-packages --clear --build-constraints build-constraints.txt --require-hashes
	rm -f dist/.gitignore

verify-artifacts:
	env -i HOME="$$HOME" PATH="$$PATH" LANG=C LC_ALL=C uv run --no-config --no-env-file --locked --all-packages python scripts/verify_artifacts.py

verifier-coverage: verify-artifacts
	uv run --locked --all-packages python -m coverage erase --data-file=.coverage.verifiers
	uv run --locked --all-packages python -m coverage run --branch --source=scripts --data-file=.coverage.verifiers -m pytest -q --no-cov tests/test_artifact_verifier.py tests/unit/test_secret_scanner.py
	uv run --locked --all-packages python -m coverage report --data-file=.coverage.verifiers --include=scripts/verify_artifacts.py --fail-under=90
	uv run --locked --all-packages python -m coverage report --data-file=.coverage.verifiers --include=scripts/verify_secret_scanner.py --fail-under=90

refresh-build-constraints:
	uv export --locked --offline --only-group build-backend --no-emit-workspace --no-header --no-annotate --output-file build-constraints.txt

check: lint typecheck test verifier-coverage

doctor:
	uv run --locked python -m cairnvm doctor
