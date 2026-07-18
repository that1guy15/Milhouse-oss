.PHONY: setup test docs-check skill-check secret-scan

setup:
	./setup.sh

test:
	python3 -m pytest

docs-check:
	test -f README.md
	test -f docs/architecture.md
	test -f docs/project-plan.md
	test -f docs/agents-and-tools.md
	test -f docs/feedback-loop.md
	test -f SECURITY.md

skill-check:
	test -f skills/milhouse-ops/SKILL.md
	test -f skills/milhouse-feedback/SKILL.md
	test -f skills/milhouse-oss-maintainer/SKILL.md
	python3 -c 'from pathlib import Path; [(__import__("sys").exit(f"invalid skill: {p}") if not (t := p.read_text()).startswith("---\n") or "name:" not in t.split("---", 2)[1] or "description:" not in t.split("---", 2)[1] else None) for p in Path("skills").glob("*/SKILL.md")]; print("skills present")'

secret-scan:
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks detect --no-git --source .; \
	else \
		echo "gitleaks not installed; using lightweight grep fallback"; \
		find . \( -path ./.git -o -path ./.venv -o -path ./data -o -path ./spool -o -path ./logs -o -path ./reports/generated \) -prune -o -type f -print0 \
			| xargs -0 grep -nE "(TOKEN|SECRET|PASSWORD|API_KEY)=['\\\"]?[A-Za-z0-9_./+=-]{8,}|account_id = \\\"[0-9a-f]{16,}" || true; \
	fi
