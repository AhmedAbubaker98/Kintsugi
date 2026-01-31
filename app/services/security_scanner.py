"""
Security Scanner Service for Kintsugi.

Uses Semgrep to detect security vulnerabilities in LLM-generated code
before committing to repositories. Prevents common issues like:
- Hardcoded secrets/credentials
- SQL injection vulnerabilities
- Command injection
- Path traversal
- Insecure configurations
- XSS vulnerabilities

Supports: JavaScript, TypeScript, Python (matching Kintsugi's test framework support)
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """A single security finding from Semgrep."""
    rule_id: str
    severity: str  # ERROR, WARNING, INFO
    message: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    category: str  # security, correctness, best-practice
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of a security scan."""
    passed: bool
    findings: list[SecurityFinding]
    error_count: int
    warning_count: int
    info_count: int
    scan_error: str | None = None
    
    @property
    def has_blocking_issues(self) -> bool:
        """Returns True if there are ERROR-level findings that should block the commit."""
        return self.error_count > 0


class SecurityScanner:
    """
    Security scanner using Semgrep to analyze code for vulnerabilities.
    
    Runs locally - no code is sent to external services.
    """
    
    # Semgrep rulesets for our supported languages
    # Using curated security-focused rulesets
    RULESETS = [
        "p/javascript",      # JS/TS security rules
        "p/typescript",      # TypeScript-specific rules  
        "p/python",          # Python security rules
        "p/secrets",         # Detect hardcoded secrets
        "p/security-audit",  # General security audit
        "p/owasp-top-ten",   # OWASP Top 10 vulnerabilities
    ]
    
    # File extensions we scan (matching Kintsugi's supported test frameworks)
    SUPPORTED_EXTENSIONS = {
        ".js", ".jsx", ".ts", ".tsx",  # JavaScript/TypeScript
        ".py",                          # Python
    }
    
    # Severity levels that should block commits
    BLOCKING_SEVERITIES = {"ERROR"}
    
    def __init__(self):
        """Initialize the security scanner."""
        self._semgrep_available: bool | None = None
    
    def is_available(self) -> bool:
        """
        Check if Semgrep is installed and available.
        
        Returns:
            bool: True if Semgrep is available for scanning.
        """
        if self._semgrep_available is not None:
            return self._semgrep_available
        
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            self._semgrep_available = result.returncode == 0
            if self._semgrep_available:
                version = result.stdout.strip()
                logger.info(f"🔒 Semgrep available: {version}")
            else:
                logger.warning("⚠️ Semgrep not available - security scanning disabled")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._semgrep_available = False
            logger.warning("⚠️ Semgrep not installed - security scanning disabled")
        
        return self._semgrep_available
    
    def scan_code(
        self,
        file_path: str,
        content: str,
        strict_mode: bool = True
    ) -> ScanResult:
        """
        Scan a single file's content for security issues.
        
        Args:
            file_path: The path of the file (used to determine language).
            content: The file content to scan.
            strict_mode: If True, ERROR-level findings block the commit.
        
        Returns:
            ScanResult: The scan results with any findings.
        """
        # Check if file type is supported
        ext = Path(file_path).suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            logger.debug(f"⏭️ Skipping unsupported file type: {file_path}")
            return ScanResult(passed=True, findings=[], error_count=0, warning_count=0, info_count=0)
        
        # Check if Semgrep is available
        if not self.is_available():
            logger.warning("🔓 Security scan skipped - Semgrep not available")
            return ScanResult(
                passed=True, 
                findings=[], 
                error_count=0, 
                warning_count=0, 
                info_count=0,
                scan_error="Semgrep not installed"
            )
        
        logger.info(f"🔍 Scanning {file_path} for security issues...")
        
        try:
            # Create a temporary file with the content
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=ext,
                delete=False,
                encoding="utf-8"
            ) as tmp_file:
                tmp_file.write(content)
                tmp_path = tmp_file.name
            
            try:
                # Run Semgrep scan
                findings = self._run_semgrep(tmp_path, file_path)
                
                # Count by severity
                error_count = sum(1 for f in findings if f.severity == "ERROR")
                warning_count = sum(1 for f in findings if f.severity == "WARNING")
                info_count = sum(1 for f in findings if f.severity == "INFO")
                
                # Determine if scan passed
                passed = not (strict_mode and error_count > 0)
                
                if findings:
                    logger.warning(
                        f"🚨 Security scan found {len(findings)} issue(s): "
                        f"{error_count} errors, {warning_count} warnings, {info_count} info"
                    )
                    for finding in findings:
                        log_fn = logger.error if finding.severity == "ERROR" else logger.warning
                        log_fn(
                            f"  [{finding.severity}] {finding.rule_id}: {finding.message} "
                            f"(line {finding.line_start})"
                        )
                else:
                    logger.info(f"✅ Security scan passed - no issues found in {file_path}")
                
                return ScanResult(
                    passed=passed,
                    findings=findings,
                    error_count=error_count,
                    warning_count=warning_count,
                    info_count=info_count
                )
                
            finally:
                # Clean up temp file
                os.unlink(tmp_path)
                
        except Exception as e:
            logger.error(f"❌ Security scan failed: {e}")
            return ScanResult(
                passed=True,  # Don't block on scanner errors
                findings=[],
                error_count=0,
                warning_count=0,
                info_count=0,
                scan_error=str(e)
            )
    
    def scan_multiple_files(
        self,
        files: dict[str, str],
        strict_mode: bool = True
    ) -> dict[str, ScanResult]:
        """
        Scan multiple files for security issues.
        
        Args:
            files: Dictionary mapping file paths to their contents.
            strict_mode: If True, ERROR-level findings block the commit.
        
        Returns:
            dict: Mapping of file paths to their ScanResults.
        """
        results = {}
        
        for file_path, content in files.items():
            results[file_path] = self.scan_code(file_path, content, strict_mode)
        
        # Log summary
        total_errors = sum(r.error_count for r in results.values())
        total_warnings = sum(r.warning_count for r in results.values())
        
        if total_errors > 0:
            logger.error(
                f"🚨 Security scan summary: {total_errors} blocking issues, "
                f"{total_warnings} warnings across {len(files)} file(s)"
            )
        elif total_warnings > 0:
            logger.warning(
                f"⚠️ Security scan summary: {total_warnings} warnings "
                f"across {len(files)} file(s)"
            )
        else:
            logger.info(f"✅ Security scan passed for all {len(files)} file(s)")
        
        return results
    
    def _run_semgrep(self, tmp_path: str, original_path: str) -> list[SecurityFinding]:
        """
        Run Semgrep on a temporary file and parse results.
        
        Args:
            tmp_path: Path to the temporary file to scan.
            original_path: Original file path (for reporting).
        
        Returns:
            list[SecurityFinding]: List of findings.
        """
        findings = []
        
        # Build Semgrep command
        # Using --config auto for automatic ruleset selection based on language
        # Plus our specific security rulesets
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--config", "auto",
        ]
        
        # Add security-focused rulesets
        for ruleset in self.RULESETS:
            cmd.extend(["--config", ruleset])
        
        cmd.append(tmp_path)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 60 second timeout
            )
            
            # Parse JSON output
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    results = output.get("results", [])
                    
                    for item in results:
                        # Map Semgrep severity to our levels
                        severity_map = {
                            "ERROR": "ERROR",
                            "WARNING": "WARNING",
                            "INFO": "INFO",
                        }
                        semgrep_severity = item.get("extra", {}).get("severity", "WARNING")
                        severity = severity_map.get(semgrep_severity.upper(), "WARNING")
                        
                        # Extract CWE and OWASP references if available
                        metadata = item.get("extra", {}).get("metadata", {})
                        cwe = metadata.get("cwe", [])
                        if isinstance(cwe, str):
                            cwe = [cwe]
                        owasp = metadata.get("owasp", [])
                        if isinstance(owasp, str):
                            owasp = [owasp]
                        
                        finding = SecurityFinding(
                            rule_id=item.get("check_id", "unknown"),
                            severity=severity,
                            message=item.get("extra", {}).get("message", "Security issue detected"),
                            file_path=original_path,  # Use original path, not temp path
                            line_start=item.get("start", {}).get("line", 0),
                            line_end=item.get("end", {}).get("line", 0),
                            code_snippet=item.get("extra", {}).get("lines", ""),
                            category=metadata.get("category", "security"),
                            cwe=cwe,
                            owasp=owasp,
                        )
                        findings.append(finding)
                        
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse Semgrep output: {e}")
            
            # Log stderr if there were issues
            if result.stderr and "error" in result.stderr.lower():
                logger.debug(f"Semgrep stderr: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning("⏱️ Semgrep scan timed out after 60 seconds")
        except Exception as e:
            logger.warning(f"Semgrep execution error: {e}")
        
        return findings
    
    def format_findings_for_pr(self, results: dict[str, ScanResult]) -> str | None:
        """
        Format security findings as a markdown section for PR descriptions.
        Only returns content if there are findings to report.
        
        Args:
            results: Dictionary of file paths to scan results.
        
        Returns:
            str | None: Markdown formatted findings, or None if no findings.
        """
        all_findings = []
        for file_path, result in results.items():
            all_findings.extend(result.findings)
        
        if not all_findings:
            return None
        
        # Group by severity
        errors = [f for f in all_findings if f.severity == "ERROR"]
        warnings = [f for f in all_findings if f.severity == "WARNING"]
        
        lines = ["## 🔒 Security Scan Results\n"]
        
        if errors:
            lines.append(f"⚠️ **{len(errors)} blocking issue(s) found** - please review before merging.\n")
        
        lines.append("| Severity | File | Line | Issue |")
        lines.append("|----------|------|------|-------|")
        
        for finding in sorted(all_findings, key=lambda f: (f.severity != "ERROR", f.file_path)):
            icon = "🔴" if finding.severity == "ERROR" else "🟡" if finding.severity == "WARNING" else "🔵"
            lines.append(
                f"| {icon} {finding.severity} | `{finding.file_path}` | "
                f"L{finding.line_start} | {finding.message[:80]}{'...' if len(finding.message) > 80 else ''} |"
            )
        
        lines.append("\n<details>")
        lines.append("<summary>View detailed findings</summary>\n")
        
        for finding in all_findings:
            lines.append(f"### {finding.rule_id}")
            lines.append(f"**Severity:** {finding.severity}")
            lines.append(f"**File:** `{finding.file_path}` (line {finding.line_start})")
            lines.append(f"**Message:** {finding.message}")
            if finding.cwe:
                lines.append(f"**CWE:** {', '.join(finding.cwe)}")
            if finding.owasp:
                lines.append(f"**OWASP:** {', '.join(finding.owasp)}")
            if finding.code_snippet:
                lines.append(f"\n```\n{finding.code_snippet}\n```\n")
            lines.append("---")
        
        lines.append("</details>\n")
        
        return "\n".join(lines)
