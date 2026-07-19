.PHONY: setup test docs-check skill-check secret-scan

setup:
	./setup.sh

test:
	python3 -m pytest

docs-check:
	test -f README.md
	test -f AGENTS.md
	test -f CODEX.md
	test -f CLAUDE.md
	test -f docs/architecture.md
	test -f docs/project-plan.md
	test -f docs/agents-and-tools.md
	test -f docs/feedback-loop.md
	test -f docs/implementation-plan.md
	test -f docs/implementation-status.md
	test -f docs/provenance.md
	test -f docs/skill-evaluations.md
	test -f docs/adr/README.md
	test -f docs/adr/0015-agent-engineering-workflow.md
	test -f docs/solutions/README.md
	test -f SECURITY.md

skill-check:
	python3 scripts/validate_skills.py

secret-scan:
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --no-git --source .; \
	else \
		echo "gitleaks not installed; using lightweight grep fallback"; \
		find . \( -path ./.git -o -path ./.venv -o -path ./data -o -path ./spool -o -path ./logs -o -path ./reports/generated \) -prune -o -type f -print0 \
			| xargs -0 grep -nE "(TOKEN|SECRET|PASSWORD|API_KEY)=['\\\"]?[A-Za-z0-9_./+=-]{8,}|account_id = \\\"[0-9a-f]{16,}" || true; \
	fi
