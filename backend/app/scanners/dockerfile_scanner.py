"""
ironclad/app/scanners/dockerfile_scanner.py
Static analysis scanner for Dockerfile payloads.
Checks for common security misconfigurations via regex/string analysis.
"""

from __future__ import annotations

import re
from uuid import UUID

from app.scanners.base_scanner import BaseScanner, Finding, ScanResult, Severity


class DockerfileScanner(BaseScanner):

    scanner_id = "dockerfile_scanner"
    scanner_version = "1.0.0"
    display_name = "Dockerfile Static Analyser"

    # ── Rule patterns ─────────────────────────────────────────────────────────

    _RE_FROM        = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)
    _RE_USER        = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
    _RE_EXPOSE      = re.compile(r"^\s*EXPOSE\s+([\d\s]+)", re.IGNORECASE | re.MULTILINE)
    _RE_LATEST_TAG  = re.compile(r"^([^:@\s]+)(?::latest)?$", re.IGNORECASE)
    _RE_ADD_URL     = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE | re.MULTILINE)
    _RE_SUDO        = re.compile(r"\bsudo\b")
    _RE_RUN         = re.compile(r"^\s*RUN\s+(.+)", re.IGNORECASE | re.MULTILINE)
    _RE_SECRET_ENV  = re.compile(
        r"^\s*ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|API_KEY)\S*\s*=?\s*\S+",
        re.IGNORECASE | re.MULTILINE,
    )
    _PRIVILEGED_USERS = {"root", "0"}

    # ─────────────────────────────────────────────────────────────────────────

    def can_handle(self, payload_type: str) -> bool:
        return payload_type.lower() == "dockerfile"

    async def scan(self, scan_id: UUID, content: str, **kwargs) -> ScanResult:
        findings: list[Finding] = []
        lines = content.splitlines()

        self._check_root_user(content, lines, findings)
        self._check_mutable_tags(content, lines, findings)
        self._check_exposed_ssh(content, lines, findings)
        self._check_add_remote_url(content, lines, findings)
        self._check_sudo_usage(content, lines, findings)
        self._check_secrets_in_env(content, lines, findings)

        return ScanResult(
            scan_id=scan_id,
            scanner_id=self.scanner_id,
            scanner_version=self.scanner_version,
            findings=findings,
            metadata={
                "lines_analysed": len(lines),
                "rules_checked": 6,
            },
        )

    # ── Rule implementations ──────────────────────────────────────────────────

    def _check_root_user(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF001 — Fails if no USER directive switches away from root.
        A Dockerfile that never sets USER runs all subsequent commands as root,
        which means any RCE in the container process has immediate root privileges.
        """
        user_matches = self._RE_USER.findall(content)
        non_root = [u for u in user_matches if u.lower() not in self._PRIVILEGED_USERS]

        if not non_root:
            findings.append(Finding(
                rule_id="DF001",
                title="Container runs as root",
                severity=Severity.CRITICAL,
                description=(
                    "No USER directive found that switches to a non-root user. "
                    "All container processes will run as uid 0, granting an attacker "
                    "full container filesystem access on exploitation."
                ),
                remediation=(
                    "Add a non-root user and switch to it before the final CMD/ENTRYPOINT:\n"
                    "  RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n"
                    "  USER appuser"
                ),
                references=[
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                ],
            ))

    def _check_mutable_tags(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF002 — Fails if any FROM uses :latest or has no tag.
        Mutable tags make builds non-reproducible and can silently pull a
        compromised upstream image.
        """
        for match in self._RE_FROM.finditer(content):
            image_ref = match.group(1).strip()

            # Skip build-arg references — can't resolve at static analysis time
            if image_ref.startswith("$"):
                continue

            # Digest-pinned images (sha256:...) are acceptable
            if "@sha256:" in image_ref:
                continue

            # Flag if no tag, or explicit :latest
            has_tag = ":" in image_ref
            is_latest = image_ref.lower().endswith(":latest")

            if not has_tag or is_latest:
                line_no = self._line_number(lines, match.group(0).strip())
                findings.append(Finding(
                    rule_id="DF002",
                    title="Mutable or untagged base image",
                    severity=Severity.HIGH,
                    description=(
                        f"Base image '{image_ref}' uses a mutable tag (or no tag). "
                        "Pulling ':latest' (or an untagged image) is non-deterministic — "
                        "a future build may silently use a different, potentially "
                        "vulnerable or compromised image."
                    ),
                    line_number=line_no,
                    snippet=match.group(0).strip(),
                    remediation=(
                        f"Pin to a specific immutable digest or version tag, e.g.:\n"
                        f"  FROM {image_ref.split(':')[0]}:1.27.4\n"
                        f"  # or for maximum reproducibility:\n"
                        f"  FROM {image_ref.split(':')[0]}@sha256:<digest>"
                    ),
                    references=[
                        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from",
                    ],
                ))

    def _check_exposed_ssh(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF003 — Fails if port 22 is exposed.
        SSH in containers is an anti-pattern; use `docker exec` for shell access.
        An exposed port 22 dramatically expands the attack surface.
        """
        for match in self._RE_EXPOSE.finditer(content):
            ports_str = match.group(1)
            exposed_ports = [p.strip() for p in ports_str.split() if p.strip()]
            if "22" in exposed_ports:
                line_no = self._line_number(lines, match.group(0).strip())
                findings.append(Finding(
                    rule_id="DF003",
                    title="SSH port 22 exposed",
                    severity=Severity.CRITICAL,
                    description=(
                        "Port 22 (SSH) is exposed in the Dockerfile. Running SSH inside "
                        "a container is an anti-pattern that substantially increases the "
                        "attack surface. Brute-force and credential-stuffing attacks "
                        "become a direct vector into the container."
                    ),
                    line_number=line_no,
                    snippet=match.group(0).strip(),
                    remediation=(
                        "Remove the SSH daemon and EXPOSE 22 entirely.\n"
                        "Use 'docker exec -it <container> /bin/sh' for interactive access,\n"
                        "or a dedicated bastion/sidecar pattern for remote shell requirements."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-4-do-not-use-ssh-in-containers",
                    ],
                ))

    def _check_add_remote_url(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF004 — Warns if ADD is used to fetch a remote URL.
        ADD with a URL fetches at build time with no checksum validation.
        Prefer RUN curl ... | sha256sum -c followed by explicit extraction.
        """
        for match in self._RE_ADD_URL.finditer(content):
            line_no = self._line_number(lines, match.group(0).strip())
            findings.append(Finding(
                rule_id="DF004",
                title="ADD used to fetch remote URL",
                severity=Severity.MEDIUM,
                description=(
                    "ADD is being used to download a remote URL. Unlike COPY, ADD "
                    "provides no checksum verification, making it vulnerable to "
                    "supply-chain attacks or content substitution."
                ),
                line_number=line_no,
                snippet=match.group(0).strip(),
                remediation=(
                    "Replace with RUN curl/wget and validate the checksum explicitly:\n"
                    "  RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz \\\n"
                    "   && echo '<expected-sha256>  /tmp/file.tar.gz' | sha256sum -c \\\n"
                    "   && tar -xzf /tmp/file.tar.gz"
                ),
                references=[
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
                ],
            ))

    def _check_sudo_usage(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF005 — Warns on sudo usage inside RUN instructions.
        If a non-root USER is set but sudo is available, privilege escalation
        within the container remains trivial.
        """
        for match in self._RE_RUN.finditer(content):
            run_body = match.group(1)
            if self._RE_SUDO.search(run_body):
                line_no = self._line_number(lines, match.group(0).strip())
                findings.append(Finding(
                    rule_id="DF005",
                    title="sudo invoked inside RUN instruction",
                    severity=Severity.MEDIUM,
                    description=(
                        "A RUN instruction calls sudo. If sudo is installed and configured "
                        "inside the image, any process running as the container user can "
                        "trivially escalate to root, negating any USER directive."
                    ),
                    line_number=line_no,
                    snippet=match.group(0).strip()[:120],
                    remediation=(
                        "Restructure the Dockerfile so privileged operations (package installs, "
                        "directory creation) occur before the USER directive, as root. "
                        "Do not install sudo into production images."
                    ),
                ))

    def _check_secrets_in_env(
        self, content: str, lines: list[str], findings: list[Finding]
    ) -> None:
        """
        DF006 — Fails if ENV is used to store secrets/credentials.
        ENV values are baked into image layers and visible via `docker inspect`.
        """
        for match in self._RE_SECRET_ENV.finditer(content):
            line_no = self._line_number(lines, match.group(0).strip())
            findings.append(Finding(
                rule_id="DF006",
                title="Secret or credential stored in ENV directive",
                severity=Severity.CRITICAL,
                description=(
                    "An ENV directive appears to store a secret, password, token, or API key. "
                    "ENV values are baked into every image layer, visible in plain text via "
                    "'docker inspect', and leaked into any image pushed to a registry."
                ),
                line_number=line_no,
                snippet="<redacted — matched secret ENV pattern>",
                remediation=(
                    "Never store secrets in ENV. Use runtime secret injection instead:\n"
                    "  • Docker secrets (Swarm): docker secret create / --secret flag\n"
                    "  • Kubernetes: secretKeyRef in env[].valueFrom\n"
                    "  • At runtime: pass via -e or a secrets manager (Vault, AWS SSM)"
                ),
                references=[
                    "https://docs.docker.com/engine/swarm/secrets/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                ],
            ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _line_number(lines: list[str], snippet: str) -> int | None:
        """Return 1-based line number of the first line containing snippet."""
        first = snippet.splitlines()[0].strip().lower()
        for i, line in enumerate(lines, start=1):
            if first in line.lower():
                return i
        return None
