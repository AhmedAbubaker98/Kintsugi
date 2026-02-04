import logging
import zipfile
import io
import os
import asyncio
import base64
import time
import re
import json
from datetime import datetime
from pathlib import PurePosixPath
from typing import Optional
from pydantic import BaseModel, Field
from app.services.github_service import GitHubService
from app.services.gemini_service import GeminiService, FixResponse
from app.services.config_service import ConfigService
from app.services.security_scanner import SecurityScanner, ScanResult
from app.schemas.config import KintsugiConfig

logger = logging.getLogger(__name__)

# Kintsugi metadata file stored in the fix branch
KINTSUGI_METADATA_FILE = ".kintsugi/fix_metadata.json"


class EvidenceUsed(BaseModel):
    """Track which evidence sources were available."""
    screenshot: bool = False
    video: bool = False
    dom_snapshot: bool = False
    error_log: bool = True  # Always have this


class AttemptRecord(BaseModel):
    """Record of a single fix attempt."""
    attempt_number: int
    timestamp: str
    error_summary: str = ""  # Brief summary of the error that triggered this attempt
    files_changed: list[str] = Field(default_factory=list)


class KintsugiFixMetadata(BaseModel):
    """
    Metadata about the fix process, stored in the branch.
    This allows us to build a high-fidelity PR report on success.
    """
    # Origin info
    base_branch: str
    original_run_id: int
    primary_file: str
    
    # Evidence tracking
    evidence_used: EvidenceUsed = Field(default_factory=EvidenceUsed)
    
    # AI reasoning (from the latest successful analysis)
    thought_process: str = ""
    explanation: str = ""
    
    # Attempt history
    attempts: list[AttemptRecord] = Field(default_factory=list)
    
    # Timestamps
    started_at: str = ""
    last_updated_at: str = ""


# Common test file patterns for different frameworks
# These match STANDARDIZED test framework output formats
FILE_PATTERNS = [
    # Playwright standardized output: "1) [chromium] › tests/e2e/file.spec.js:10:5 › Suite › test"
    r'\[(?:chromium|firefox|webkit)\]\s*›\s*([^\s:›]+\.(?:spec|test)\.[jt]sx?)(?::\d+)?',
    # Playwright error stack: "at tests/e2e/file.spec.js:15:10"
    r'at\s+([^\s:]+\.(?:spec|test)\.[jt]sx?):\d+',
    # Jest standardized output: "FAIL tests/example.test.js" or "● Test Suite › test name"  
    r'FAIL\s+([^\s]+\.(?:spec|test)\.[jt]sx?)',
    r'●\s+([^\s]+\.(?:spec|test)\.[jt]sx?)',
    # Cypress standardized: "Running: cypress/e2e/file.cy.js"
    r'Running:\s*([^\s]+\.cy\.[jt]sx?)',
    # Pytest standardized: "FAILED tests/test_file.py::test_name" or "tests/test_file.py:10: AssertionError"
    r'FAILED\s+([^\s:]+\.py)(?:::|:)',
    r'([^\s:]+_test\.py|[^\s:]+test_[^\s:]+\.py):\d+:',
    # Mocha: "1) Suite name test name" followed by "at Context.<anonymous> (test/file.js:10:5)"
    r'at\s+(?:Context\.<anonymous>|Object\.<anonymous>)\s*\(([^\s:)]+\.(?:spec|test)\.[jt]sx?):\d+',
    # Generic error stack traces with test paths
    r'(?:Error|AssertionError|TimeoutError)[^\n]*\n\s+at[^\n]*\n\s+at\s+([^\s:()]+/(?:tests?|e2e|spec|__tests__)/[^\s:()]+\.[jt]sx?):\d+',
]

# CI/CD infrastructure failure patterns - Kintsugi should NOT try to fix these
CI_INFRASTRUCTURE_FAILURE_PATTERNS = [
    # Package manager / dependency issues
    r'Dependencies lock file is not found',
    r'package-lock\.json.*not found',
    r'yarn\.lock.*not found',
    r'pnpm-lock\.yaml.*not found',
    r'npm ERR! code E(RESOLVE|NOENT|NOTFOUND)',
    r'npm ERR! Could not resolve dependency',
    r'npm ci.*can only install packages when.*package-lock\.json',
    r'pip install.*failed|Could not find a version that satisfies',
    r'ModuleNotFoundError:.*No module named',
    # Docker / container issues
    r'docker:.*not found|Cannot connect to the Docker daemon',
    r'Error response from daemon',
    # GitHub Actions setup issues
    r'Error: (Setup|Install|Configure).*failed',
    r'Unable to resolve action',
    r'Node\.js.*is not.*supported',
    r'Python.*is not.*supported',
    # Network / auth issues
    r'Could not resolve host',
    r'ECONNREFUSED|ETIMEDOUT|ENOTFOUND',
    r'401 Unauthorized|403 Forbidden',
    r'rate limit exceeded',
    # Resource / permission issues
    r'ENOSPC|No space left on device',
    r'ENOMEM|Cannot allocate memory',
    r'Permission denied',
    # Build tool issues (not test failures)
    r'tsc.*error TS\d+',  # TypeScript compilation errors
    r'SyntaxError:.*Unexpected token',  # JS syntax errors at build time
    r'Build failed|Compilation failed',
    # Port / server conflicts (CI starts server separately)
    r'is already used, make sure that nothing is running',
    r'address already in use|EADDRINUSE',
    r'port \d+ is already allocated',
]

# Import patterns for different languages (more comprehensive)
JS_IMPORT_PATTERNS = [
    # ES6 imports: import x from './path' or import { x } from './path'
    r'import\s+(?:[\w{}\s*,]+\s+from\s+)?["\']([^"\']+)["\']',
    # CommonJS: require('./path')
    r'require\s*\(\s*["\']([^"\']+)["\']\s*\)',
    # Dynamic imports: import('./path')
    r'import\s*\(\s*["\']([^"\']+)["\']\s*\)',
]

PYTHON_IMPORT_PATTERNS = [
    # from .module import x
    r'from\s+(\.[^\s]+)\s+import',
    # import .module
    r'import\s+(\.[^\s]+)',
    # from local_module import x (non-relative but local)
    r'from\s+([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*)\s+import',
]

# Extensions to try when resolving imports
JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.json', '/index.ts', '/index.js']
PYTHON_EXTENSIONS = ['.py', '/__init__.py']


class WorkflowProcessor:
    def __init__(self):
        self.github = GitHubService()
        self.gemini = GeminiService()
        self.config_service = ConfigService(self.github)
        self.security_scanner = SecurityScanner()

    async def process_failure(self, installation_id: int, repo_full_name: str, run_id: int, branch: str = "main"):
        """
        Orchestrates the Silent self-healing pipeline.
        
        Workflow:
        - Main branch fails → Create kintsugi-fix-*, push fix, NO PR
        - kintsugi-fix-* fails → Check attempts, iterate with new fix, NO PR
        - kintsugi-fix-* passes → NOW create PR with full report (handled by handle_kintsugi_success)
        - Max attempts reached → Create PR with failure report
        
        The PR only surfaces upon success or final failure, respecting notification bandwidth.
        """
        try:
            # 1. Authenticate as the App
            token = await self.github.get_installation_token(installation_id)
            logger.info(f"🔐 Authenticated for repo {repo_full_name}")
            owner, repo = repo_full_name.split("/")

            # 2. Load Repository Configuration
            # For kintsugi branches, load config from base branch
            config_ref = branch if not branch.startswith("kintsugi-fix") else "main"
            config = await self.config_service.get_config(installation_id, owner, repo, ref=config_ref)
            
            # 2.5. Check if Kintsugi is enabled for this repo
            if not config.enabled:
                logger.info(f"⏸️ Kintsugi is disabled for {repo_full_name}. Skipping.")
                return
            
            # 3. DEMO PASSWORD VALIDATION (Hackathon protection)
            from app.core.config import settings
            expected_password = settings.judge_password.get_secret_value()
            if expected_password:  # Only validate if server has a password set
                if config.demo_password != expected_password:
                    logger.warning(
                        f"🚫 Invalid or missing demo_password for {repo_full_name}. "
                        "Kintsugi is currently in a restricted demo mode."
                    )
                    return
                logger.info(f"✅ Demo password validated for {repo_full_name}. Proceeding.")
            
            # 4. Check if this is an iteration on an existing kintsugi branch
            is_iteration = branch.startswith("kintsugi-fix")
            
            if is_iteration:
                # Check attempt count before proceeding
                attempt_count = await self.github.get_branch_commit_count(
                    token, repo_full_name, branch, "main"
                )
                logger.info(f"🔄 Iteration mode: Attempt #{attempt_count + 1} on branch '{branch}'")
                
                if attempt_count >= config.limits.max_attempts:
                    logger.warning(
                        f"⚠️ Max attempts ({config.limits.max_attempts}) reached for branch '{branch}'. "
                        "Opening PR with failure report."
                    )
                    await self._handle_max_attempts_reached(
                        token, installation_id, owner, repo, repo_full_name, branch, run_id, config
                    )
                    return
            else:
                # Check if original branch is allowed
                if not self.config_service.is_branch_allowed(config, branch):
                    logger.info(f"⏭️ Branch '{branch}' is not in allowed list. Skipping.")
                    return

            # 5. Download Artifacts (if available)
            artifacts = await self._get_artifacts_with_retry(token, repo_full_name, run_id)
            
            # Initialize evidence with defaults
            evidence = {"screenshot": None, "video": None, "dom_snapshot": None, "error_text": ""}
            broken_file_path = None
            artifact_downloaded = False
            
            if artifacts:
                # Log all available artifacts for debugging
                artifact_names = [a["name"] for a in artifacts]
                logger.info(f"📦 Available artifacts: {artifact_names}")
                
                # Find test-related artifacts (flexible pattern matching)
                target_artifact = next(
                    (a for a in artifacts if any(
                        keyword in a["name"].lower() 
                        for keyword in ["report", "results", "test", "playwright", "cypress", "jest", "pytest", "evidence", "gauntlet", "artifact"]
                    )),
                    None
                )
                
                if target_artifact:
                    logger.info(f"📦 Selected Artifact: {target_artifact['name']} (ID: {target_artifact['id']})")
                    zip_content = await self.github.download_artifact(installation_id, owner, repo, target_artifact["id"])
                    
                    # Extract Evidence (screenshot + video + DOM + error log)
                    evidence = await self._extract_evidence(zip_content)
                    artifact_downloaded = True
                    
                    # Dynamic File Discovery - Identify broken file from error log
                    broken_file_path = self._identify_broken_file(evidence["error_text"])
                else:
                    logger.warning(f"No test report artifact matched patterns. Available: {artifact_names}")
            
            # 5.5. Fetch workflow logs (always needed for context, may also contain artifact ID)
            workflow_logs = ""
            try:
                workflow_logs = await self._fetch_workflow_logs(installation_id, owner, repo, run_id)
                if workflow_logs:
                    logger.info(f"📜 Fetched {len(workflow_logs)} chars of workflow logs")
                    
                    # If no artifact was downloaded, try to find artifact ID in logs and download
                    if not artifact_downloaded:
                        artifact_id = self._parse_artifact_id_from_logs(workflow_logs)
                        if artifact_id:
                            logger.info(f"📦 Found artifact ID in logs: {artifact_id}")
                            try:
                                zip_content = await self.github.download_artifact(installation_id, owner, repo, artifact_id)
                                evidence = await self._extract_evidence(zip_content)
                                artifact_downloaded = True
                                broken_file_path = self._identify_broken_file(evidence["error_text"])
                            except Exception as e:
                                logger.warning(f"Could not download artifact {artifact_id}: {e}")
                    
                    # Use workflow logs as error text if no artifact evidence
                    if not evidence["error_text"]:
                        evidence["error_text"] = workflow_logs
            except Exception as e:
                logger.warning(f"Could not fetch workflow logs: {e}")
                evidence["error_text"] = "No error log available."
            
            # 5.6. Check for CI infrastructure failures BEFORE proceeding
            is_infra_failure, infra_reason = self._is_infrastructure_failure(evidence["error_text"])
            if is_infra_failure:
                logger.warning(
                    f"🔧 CI INFRASTRUCTURE FAILURE detected: {infra_reason}\n"
                    "This is not a test failure - Kintsugi cannot fix this. Skipping."
                )
                return
            
            # 6. Get repository file structure for context
            fetch_branch = branch
            repo_files = await self.github.list_repository_files(token, repo_full_name, ref=fetch_branch)
            logger.info(f"📂 Repository has {len(repo_files)} files")
            
            # Fallback: If no broken file identified, try to find test files in the repo
            if not broken_file_path:
                logger.warning("Could not identify broken file from error log. Searching repo for test files...")
                broken_file_path = self._find_test_file_in_repo(repo_files)
            
            if not broken_file_path:
                logger.error("❌ Could not identify any test file to fix. Aborting.")
                return
            
            logger.info(f"🎯 Identified broken file: {broken_file_path}")

            # 7. Fetch the broken file content
            file_data = await self.github.get_repository_content(
                installation_id, owner, repo, broken_file_path, ref=fetch_branch
            )
            
            # If branch doesn't exist (deleted kintsugi branch), fall back to main
            if not file_data and branch.startswith("kintsugi-fix"):
                logger.warning(f"Branch '{branch}' not found, falling back to 'main'")
                fetch_branch = "main"
                branch = "main"
                is_iteration = False
                repo_files = await self.github.list_repository_files(token, repo_full_name, ref=fetch_branch)
                file_data = await self.github.get_repository_content(
                    installation_id, owner, repo, broken_file_path, ref=fetch_branch
                )
            
            if not file_data:
                logger.error(f"Could not find file {broken_file_path} in repo.")
                return

            broken_file_content = base64.b64decode(file_data["content"]).decode("utf-8")

            # 8. Smart Context Retrieval - Parse imports and fetch related files
            context_files = await self._fetch_context_files(
                installation_id, owner, repo, fetch_branch,
                broken_file_path, broken_file_content, repo_files
            )
            logger.info(f"📚 Fetched {len(context_files)} context files")

            # 9. Determine target branch for session tracking
            if is_iteration:
                session_id = branch  # Reuse existing kintsugi branch name
            else:
                session_id = f"kintsugi-fix-{int(time.time())}"  # New branch name
            
            # 10. Call Gemini with full context (using Chat API for thought signature continuity)
            logger.info("🧠 Sending to Gemini with full context...")
            
            model_name = self.config_service.get_model_name(config)
            thinking_budget = self.config_service.get_thinking_budget(config)
            logger.info(f" Using AI model: {model_name} (mode: {config.ai.mode}, thinking: {thinking_budget})")
            
            # Log media availability for debugging
            has_screenshot = evidence["screenshot"] is not None
            has_video = evidence.get("video") is not None
            has_dom = evidence.get("dom_snapshot") is not None
            logger.info(f"📎 Media: screenshot={has_screenshot}, video={has_video}, dom={has_dom}")
            
            fix_result = self.gemini.generate_fix(
                primary_file_path=broken_file_path,
                primary_file_content=broken_file_content,
                error_log=evidence["error_text"],
                screenshot_bytes=evidence["screenshot"],
                video_bytes=evidence.get("video"),
                context_files=context_files,
                repo_file_structure=repo_files,
                extra_instructions=config.ai.extra_instructions,
                model_name=model_name,
                thinking_budget=thinking_budget,
                session_id=session_id,
                is_iteration=is_iteration,
            )

            logger.info("✨ KINTSUGI FIX GENERATED ✨")
            logger.info(f"📝 {fix_result.explanation}")
            logger.info(f"📄 {len(fix_result.fixes)} file(s) to update")

            # 11. Validate fixes against config limits
            if len(fix_result.fixes) > config.limits.max_files_changed:
                logger.warning(
                    f"⚠️ Gemini suggested {len(fix_result.fixes)} files, "
                    f"but config limits to {config.limits.max_files_changed}. Truncating."
                )
                fix_result.fixes = fix_result.fixes[:config.limits.max_files_changed]

            # 12. Check for protected files
            protected_fixes = []
            allowed_fixes = []
            for fix in fix_result.fixes:
                if self.config_service.is_path_protected(config, fix.file_path):
                    protected_fixes.append(fix.file_path)
                    logger.warning(f"🛡️ File '{fix.file_path}' is protected by config. Skipping.")
                else:
                    allowed_fixes.append(fix)
            
            if protected_fixes and not allowed_fixes:
                logger.error(
                    f"❌ All suggested fixes are in protected files: {protected_fixes}. "
                    "Cannot proceed. Consider updating .github/kintsugi.yml."
                )
                return
            
            if protected_fixes:
                logger.info(f"⏭️ Skipping protected files: {protected_fixes}")

            # 13. Security scan - check LLM-generated code for vulnerabilities
            security_passed, allowed_fixes = await self._security_scan_fixes(allowed_fixes, config)
            if not allowed_fixes:
                logger.error("❌ All fixes blocked by security scan. Aborting.")
                return

            # 14. Determine branch strategy (create or reuse)
            if is_iteration:
                # Reuse existing kintsugi branch
                target_branch = session_id
                base_branch = "main"  # TODO: Store actual base in metadata
                logger.info(f"🔄 Silent iteration: Pushing to existing branch '{target_branch}'")
            else:
                # Create new kintsugi branch (using pre-determined session_id)
                target_branch = session_id
                base_branch = branch
                
                logger.info(f"🌿 Creating new branch '{target_branch}' from '{base_branch}'...")
                branch_sha = await self.github.get_branch_sha(token, repo_full_name, base_branch)
                await self.github.create_branch(token, repo_full_name, target_branch, branch_sha)
                logger.info(f"✅ Branch '{target_branch}' created")

            # 15. Build and save metadata FIRST (before applying fixes)
            current_attempt = await self.github.get_branch_commit_count(
                token, repo_full_name, target_branch, base_branch
            ) + 1 if is_iteration else 1
            
            # Create or update metadata
            metadata = await self._get_or_create_metadata(
                token, installation_id, owner, repo, target_branch, base_branch,
                run_id, broken_file_path, evidence, fix_result, current_attempt
            )
            
            # 16. Apply all fixes in a SINGLE commit (batch)
            files_to_commit = {fix.file_path: fix.content for fix in allowed_fixes}
            
            # Include metadata in the same commit
            metadata_content = metadata.model_dump_json(indent=2)
            files_to_commit[".kintsugi/fix_metadata.json"] = metadata_content
            
            # Build commit message
            commit_msg = f"fix(kintsugi): {fix_result.explanation[:60]}"
            if len(allowed_fixes) > 1:
                commit_msg += f" (+{len(allowed_fixes)-1} files)"
            
            logger.info(f"🚑 Committing {len(allowed_fixes)} fix(es) to '{target_branch}'...")
            commit_response = await self.github.push_commit(
                installation_id=installation_id,
                owner=owner,
                repo=repo,
                branch=target_branch,
                message=commit_msg,
                files=files_to_commit,
            )
            commit_url = commit_response.get("html_url", "N/A")
            logger.info(f"✅ Committed {len(allowed_fixes)} file(s): {commit_url}")

            # 18. NO PR CREATION! Just log and wait for CI result
            logger.info(f"Fix pushed to '{target_branch}'. Waiting for CI...")
            logger.info(f"Attempt {current_attempt}/{config.limits.max_attempts}")

        except Exception as e:
            logger.error(f"❌ Error processing failure: {e}", exc_info=True)

    async def _security_scan_fixes(
        self, 
        fixes: list,
        config: KintsugiConfig | None = None
    ) -> tuple[bool, list]:
        """
        Run security scan on LLM-generated fixes before committing.
        
        Uses Semgrep to detect:
        - Hardcoded secrets/credentials
        - SQL/Command injection vulnerabilities  
        - XSS vulnerabilities
        - Path traversal issues
        - Other OWASP Top 10 vulnerabilities
        
        Args:
            fixes: List of FileFix objects from Gemini.
            config: Optional Kintsugi config for scan settings.
        
        Returns:
            tuple: (all_passed: bool, safe_fixes: list of fixes that passed)
        """
        if not fixes:
            return True, []
        
        # Check if scanning is disabled in config
        if config and not config.security.scan_enabled:
            logger.info("⏭️ Security scanning disabled in config")
            return True, fixes
        
        strict_mode = config.security.block_on_critical if config else True
        
        logger.info(f"🔒 Running security scan on {len(fixes)} file(s)...")
        
        # Build dict of files to scan
        files_to_scan = {fix.file_path: fix.content for fix in fixes}
        
        # Run the scan
        results = self.security_scanner.scan_multiple_files(files_to_scan, strict_mode=strict_mode)
        
        # Filter out fixes with blocking security issues
        safe_fixes = []
        blocked_files = []
        
        for fix in fixes:
            result = results.get(fix.file_path)
            if result and result.has_blocking_issues and strict_mode:
                blocked_files.append(fix.file_path)
                logger.error(
                    f"🚫 Security blocked: {fix.file_path} "
                    f"({result.error_count} critical issue(s))"
                )
                for finding in result.findings:
                    if finding.severity == "ERROR":
                        logger.error(
                            f"   └─ {finding.rule_id}: {finding.message} (line {finding.line_start})"
                        )
            else:
                safe_fixes.append(fix)
        
        all_passed = len(blocked_files) == 0
        
        if blocked_files:
            logger.warning(
                f"⚠️ Security scan blocked {len(blocked_files)} file(s): {blocked_files}"
            )
        else:
            logger.info("✅ Security scan passed - no blocking issues found")
        
        return all_passed, safe_fixes

    def _is_infrastructure_failure(self, error_text: str) -> tuple[bool, str | None]:
        """
        Check if the error is a CI/CD infrastructure failure that Kintsugi cannot fix.
        
        These are issues like missing lock files, dependency resolution failures,
        Docker problems, etc. - not actual test failures.
        
        Args:
            error_text: The error log content.
        
        Returns:
            tuple[bool, str | None]: (is_infrastructure_failure, matched_pattern_description)
        """
        if not error_text:
            return False, None
        
        for pattern in CI_INFRASTRUCTURE_FAILURE_PATTERNS:
            match = re.search(pattern, error_text, re.IGNORECASE)
            if match:
                matched_text = match.group(0)[:100]  # First 100 chars of match
                logger.info(f"🔧 Detected CI infrastructure failure: '{matched_text}'")
                return True, matched_text
        
        return False, None

    def _identify_broken_file(self, error_text: str) -> str | None:
        """
        Parse the error log to identify the broken test file.
        
        Args:
            error_text: The error log content.
        
        Returns:
            str | None: The identified file path or None if not found.
        """
        if not error_text:
            return None
            
        for pattern in FILE_PATTERNS:
            matches = re.findall(pattern, error_text, re.IGNORECASE)
            if matches:
                # Clean up the match - remove quotes, line numbers, etc.
                file_path = matches[0]
                # Remove line:column suffixes like :15:3
                file_path = re.sub(r':\d+:\d+$', '', file_path)
                file_path = re.sub(r':\d+$', '', file_path)
                # Remove leading ./ or /
                file_path = file_path.lstrip('./')
                
                # Validate it looks like a real file path
                if '.' in file_path and not file_path.startswith('node_modules'):
                    logger.debug(f"Found file path: {file_path} (pattern: {pattern})")
                    return file_path
        
        return None

    def _find_test_file_in_repo(self, repo_files: list[str]) -> str | None:
        """
        Search the repository file list to find a test file.
        Used as a fallback when error log parsing fails.
        
        Args:
            repo_files: List of all file paths in the repository.
        
        Returns:
            str | None: Path to a test file, or None if not found.
        """
        # Test file patterns in order of priority
        test_patterns = [
            # Playwright
            r'\.spec\.[jt]sx?$',
            r'\.test\.[jt]sx?$',
            # Cypress
            r'\.cy\.[jt]sx?$',
            # Python pytest
            r'test_.*\.py$',
            r'.*_test\.py$',
        ]
        
        # Directories that typically contain tests
        test_dirs = ['tests', 'test', 'e2e', 'spec', 'specs', '__tests__', 'cypress']
        
        # First, look for test files in known test directories
        for test_dir in test_dirs:
            for file_path in repo_files:
                if f'/{test_dir}/' in file_path or file_path.startswith(f'{test_dir}/'):
                    for pattern in test_patterns:
                        if re.search(pattern, file_path, re.IGNORECASE):
                            logger.info(f"📍 Found test file in '{test_dir}': {file_path}")
                            return file_path
        
        # Fallback: search all files for test patterns
        for pattern in test_patterns:
            for file_path in repo_files:
                if re.search(pattern, file_path, re.IGNORECASE):
                    # Skip node_modules and other dependency directories
                    if any(skip in file_path for skip in ['node_modules', 'vendor', '.git', 'dist', 'build']):
                        continue
                    logger.info(f"📍 Found test file: {file_path}")
                    return file_path
        
        return None

    def _parse_imports(self, file_content: str, file_path: str) -> list[str]:
        """
        Parse import statements from a file to find local dependencies.
        
        Args:
            file_content: The file content to parse.
            file_path: Path of the file (to determine language).
        
        Returns:
            list[str]: List of relative import paths.
        """
        imports = []
        
        # Determine language from extension
        is_python = file_path.endswith('.py')
        patterns = PYTHON_IMPORT_PATTERNS if is_python else JS_IMPORT_PATTERNS
        
        logger.debug(f"Parsing imports from {file_path} (is_python={is_python})")
        
        for pattern in patterns:
            matches = re.findall(pattern, file_content)
            logger.debug(f"  Pattern '{pattern[:30]}...' found: {matches}")
            for match in matches:
                # Filter out third-party packages (no relative path indicator)
                if is_python:
                    # Python relative imports start with .
                    if match.startswith('.'):
                        imports.append(match)
                        logger.debug(f"    ✓ Added Python import: {match}")
                else:
                    # JS/TS: Include relative imports (./  ../) and aliased paths (@/)
                    if match.startswith('.') or match.startswith('@/'):
                        imports.append(match)
                        logger.debug(f"    ✓ Added JS/TS import: {match}")
                    else:
                        logger.debug(f"    ✗ Skipped third-party: {match}")
        
        logger.info(f"📥 Parsed {len(imports)} local imports from {file_path}: {imports}")
        return imports

    def _resolve_import_path(
        self, 
        import_path: str, 
        source_file_path: str, 
        repo_files: list[str]
    ) -> str | None:
        """
        Resolve an import path to an actual file in the repository.
        
        Args:
            import_path: The import path (e.g., './helpers/login' or '../src/calculator').
            source_file_path: The file that contains the import.
            repo_files: List of all files in the repository.
        
        Returns:
            str | None: Resolved file path or None if not found.
        """
        is_python = source_file_path.endswith('.py')
        extensions = PYTHON_EXTENSIONS if is_python else JS_EXTENSIONS
        
        # Get the directory of the source file
        source_dir = str(PurePosixPath(source_file_path).parent)
        
        # Handle different import formats
        if import_path.startswith('@/'):
            # Alias - assume it maps to src/
            resolved_base = import_path.replace('@/', 'src/')
        elif import_path.startswith('.'):
            # Relative import (includes ./ and ../)
            if is_python:
                # Convert Python module path to file path
                # from .helpers import login -> ./helpers.py or ./helpers/__init__.py
                parts = import_path.split('.')
                relative_path = '/'.join(p for p in parts if p)
                combined = str(PurePosixPath(source_dir) / relative_path)
            else:
                # JS/TS: Combine source dir with import path
                combined = str(PurePosixPath(source_dir) / import_path)
            
            # Normalize path to resolve .. and . segments
            # PurePosixPath doesn't resolve .., so we need to do it manually
            resolved_base = self._normalize_path(combined)
        else:
            return None  # Not a relative import
        
        logger.debug(f"  Resolving '{import_path}' from '{source_file_path}' -> base: '{resolved_base}'")
        
        # Try with different extensions
        for ext in extensions:
            candidate = resolved_base + ext
            # Normalize the path
            candidate = self._normalize_path(candidate)
            logger.debug(f"    Trying: '{candidate}'")
            if candidate in repo_files:
                return candidate
        
        # Try exact match (maybe already has extension)
        if resolved_base in repo_files:
            return resolved_base
            
        return None

    def _normalize_path(self, path: str) -> str:
        """
        Normalize a path by resolving . and .. segments.
        
        Args:
            path: The path to normalize.
        
        Returns:
            str: Normalized path with . and .. resolved.
        """
        parts = path.split('/')
        normalized = []
        
        for part in parts:
            if part == '.' or part == '':
                continue
            elif part == '..':
                if normalized:
                    normalized.pop()
            else:
                normalized.append(part)
        
        return '/'.join(normalized)

    async def _fetch_context_files(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        branch: str,
        broken_file_path: str,
        broken_file_content: str,
        repo_files: list[str],
    ) -> dict[str, str]:
        """
        Fetch imported files to provide context to Gemini.
        
        Args:
            installation_id: GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            branch: Branch to fetch from.
            broken_file_path: Path of the broken test file.
            broken_file_content: Content of the broken test file.
            repo_files: List of all files in the repository.
        
        Returns:
            dict[str, str]: Dictionary mapping file paths to their contents.
        """
        context_files = {}
        
        # Parse imports from the broken file
        imports = self._parse_imports(broken_file_content, broken_file_path)
        
        # Resolve import paths to actual files
        files_to_fetch = []
        for imp in imports:
            resolved = self._resolve_import_path(imp, broken_file_path, repo_files)
            if resolved and resolved not in files_to_fetch:
                files_to_fetch.append(resolved)
                logger.info(f"  ✓ Resolved '{imp}' -> '{resolved}'")
            elif not resolved:
                logger.warning(f"  ✗ Could not resolve '{imp}' in repo files")
        
        logger.info(f"📚 Will fetch {len(files_to_fetch)} dependency files: {files_to_fetch}")
        
        # Fetch files in parallel
        async def fetch_file(file_path: str) -> tuple[str, str | None]:
            try:
                file_data = await self.github.get_repository_content(
                    installation_id, owner, repo, file_path, ref=branch
                )
                if file_data and "content" in file_data:
                    content = base64.b64decode(file_data["content"]).decode("utf-8")
                    return (file_path, content)
            except Exception as e:
                logger.warning(f"Could not fetch context file {file_path}: {e}")
            return (file_path, None)
        
        # Fetch all files concurrently
        results = await asyncio.gather(*[fetch_file(f) for f in files_to_fetch])
        
        for file_path, content in results:
            if content:
                context_files[file_path] = content
        
        return context_files

    async def _get_artifacts_with_retry(
        self, token: str, repo_full_name: str, run_id: int, retries: int = 3
    ) -> list:
        """Fetch artifacts with retry logic."""
        for attempt in range(retries):
            artifacts_data = await self.github.list_workflow_artifacts(token, repo_full_name, run_id)
            artifacts = artifacts_data.get("artifacts", [])
            if artifacts:
                return artifacts
            logger.info(f"Artifacts list empty, retrying in 2s (Attempt {attempt+1}/{retries})...")
            await asyncio.sleep(2)
        return []

    def _parse_artifact_id_from_logs(self, logs: str) -> int | None:
        """
        Parse artifact ID from workflow logs.
        
        GitHub Actions logs contain standardized output like:
        "Artifact <name> has been successfully uploaded! ... Artifact ID is <id>"
        "Artifact download URL: https://github.com/.../artifacts/<id>"
        
        Args:
            logs: The workflow log content.
        
        Returns:
            int | None: The artifact ID if found, None otherwise.
        """
        if not logs:
            return None
        
        # Pattern 1: "Artifact ID is <number>"
        match = re.search(r'Artifact ID is (\d+)', logs)
        if match:
            return int(match.group(1))
        
        # Pattern 2: "Artifact ID <number>"
        match = re.search(r'Artifact ID (\d+)', logs)
        if match:
            return int(match.group(1))
        
        # Pattern 3: URL pattern "/artifacts/<number>"
        match = re.search(r'/artifacts/(\d+)', logs)
        if match:
            return int(match.group(1))
        
        return None

    async def _determine_branch_strategy(
        self,
        token: str,
        repo_full_name: str,
        incoming_branch: str,
        installation_id: int,
        owner: str,
        repo: str,
    ) -> tuple[str, str, bool]:
        """
        Determine the branching strategy based on incoming branch.
        
        Returns:
            tuple: (target_branch, base_branch, is_new_branch)
        """
        # If already on a kintsugi-fix branch, reuse it (iterative healing)
        if incoming_branch.startswith("kintsugi-fix"):
            logger.info(f"🔄 Iterative mode: Reusing existing branch '{incoming_branch}'")
            # Find the base branch from the PR or default to main
            base_branch = "main"
            return (incoming_branch, base_branch, False)
        
        # Otherwise, create a new branch
        new_branch_name = f"kintsugi-fix-{int(time.time())}"
        base_branch = incoming_branch
        
        # Get the SHA of the base branch
        logger.info(f"🌿 Creating new branch '{new_branch_name}' from '{base_branch}'...")
        branch_sha = await self.github.get_branch_sha(token, repo_full_name, base_branch)
        
        # Create the new branch
        await self.github.create_branch(token, repo_full_name, new_branch_name, branch_sha)
        logger.info(f"✅ Branch '{new_branch_name}' created")
        
        return (new_branch_name, base_branch, True)

    async def _apply_fix(
        self,
        token: str,
        installation_id: int,
        owner: str,
        repo: str,
        repo_full_name: str,
        target_branch: str,
        file_path: str,
        content: str,
        explanation: str,
    ):
        """Apply a single file fix by committing to the target branch."""
        logger.info(f"🚑 Pushing fix to '{file_path}' on branch '{target_branch}'...")
        
        # Get current file SHA for the update
        file_data = await self.github.get_repository_content(
            installation_id, owner, repo, file_path, ref=target_branch
        )
        
        if not file_data:
            logger.error(f"Could not find {file_path} on branch {target_branch}")
            return
            
        current_sha = file_data["sha"]
        
        commit_response = await self.github.update_file(
            token=token,
            repo_full_name=repo_full_name,
            path=file_path,
            message=f"fix(kintsugi): {explanation[:50]}",
            content=content,
            sha=current_sha,
            branch=target_branch,
        )
        
        commit_url = commit_response.get("commit", {}).get("html_url", "N/A")
        logger.info(f"✅ Committed {file_path}: {commit_url}")

    async def _get_or_create_metadata(
        self,
        token: str,
        installation_id: int,
        owner: str,
        repo: str,
        target_branch: str,
        base_branch: str,
        run_id: int,
        primary_file: str,
        evidence: dict,
        fix_result: FixResponse,
        attempt_number: int,
    ) -> KintsugiFixMetadata:
        """
        Get existing metadata from branch or create new metadata.
        
        Args:
            Various context about the fix being applied.
        
        Returns:
            KintsugiFixMetadata: The metadata object (existing or new).
        """
        # Try to fetch existing metadata
        existing_metadata = await self._fetch_metadata(
            installation_id, owner, repo, target_branch
        )
        
        now = datetime.utcnow().isoformat() + "Z"
        
        if existing_metadata:
            # Update existing metadata with new attempt
            existing_metadata.thought_process = fix_result.thought_process
            existing_metadata.explanation = fix_result.explanation
            existing_metadata.last_updated_at = now
            
            # Update evidence (might have changed between attempts)
            existing_metadata.evidence_used.screenshot = evidence.get("screenshot") is not None
            existing_metadata.evidence_used.video = evidence.get("video") is not None
            existing_metadata.evidence_used.dom_snapshot = evidence.get("dom_snapshot") is not None
            
            # Add new attempt record
            error_summary = self._extract_error_summary(evidence.get("error_text", ""))
            existing_metadata.attempts.append(AttemptRecord(
                attempt_number=attempt_number,
                timestamp=now,
                error_summary=error_summary,
                files_changed=[f.file_path for f in fix_result.fixes],
            ))
            
            return existing_metadata
        else:
            # Create new metadata
            error_summary = self._extract_error_summary(evidence.get("error_text", ""))
            return KintsugiFixMetadata(
                base_branch=base_branch,
                original_run_id=run_id,
                primary_file=primary_file,
                evidence_used=EvidenceUsed(
                    screenshot=evidence.get("screenshot") is not None,
                    video=evidence.get("video") is not None,
                    dom_snapshot=evidence.get("dom_snapshot") is not None,
                ),
                thought_process=fix_result.thought_process,
                explanation=fix_result.explanation,
                attempts=[AttemptRecord(
                    attempt_number=attempt_number,
                    timestamp=now,
                    error_summary=error_summary,
                    files_changed=[f.file_path for f in fix_result.fixes],
                )],
                started_at=now,
                last_updated_at=now,
            )

    async def _fetch_metadata(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        branch: str,
    ) -> Optional[KintsugiFixMetadata]:
        """Fetch existing metadata from the branch if it exists."""
        try:
            file_data = await self.github.get_repository_content(
                installation_id, owner, repo, KINTSUGI_METADATA_FILE, ref=branch
            )
            if file_data and "content" in file_data:
                content = base64.b64decode(file_data["content"]).decode("utf-8")
                return KintsugiFixMetadata.model_validate_json(content)
        except Exception as e:
            logger.debug(f"No existing metadata found: {e}")
        return None

    async def _save_metadata(
        self,
        token: str,
        installation_id: int,
        owner: str,
        repo: str,
        repo_full_name: str,
        branch: str,
        metadata: KintsugiFixMetadata,
    ):
        """Save metadata file to the branch."""
        try:
            content = metadata.model_dump_json(indent=2)
            
            # Check if file already exists
            existing = await self.github.get_repository_content(
                installation_id, owner, repo, KINTSUGI_METADATA_FILE, ref=branch
            )
            
            if existing:
                # Update existing file
                await self.github.update_file(
                    token=token,
                    repo_full_name=repo_full_name,
                    path=KINTSUGI_METADATA_FILE,
                    message="chore(kintsugi): Update fix metadata",
                    content=content,
                    sha=existing["sha"],
                    branch=branch,
                )
            else:
                # Create new file using the create contents API
                await self._create_file(
                    token, repo_full_name, KINTSUGI_METADATA_FILE,
                    content, branch, "chore(kintsugi): Add fix metadata"
                )
            
            logger.debug(f"📝 Saved metadata to {KINTSUGI_METADATA_FILE}")
        except Exception as e:
            logger.warning(f"Failed to save metadata: {e}")

    async def _cleanup_metadata_file(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        branch: str,
    ):
        """
        Delete the .kintsugi/fix_metadata.json file from the branch.
        
        Called after PR is created if cleanup_metadata is enabled in config.
        This prevents the metadata file from being merged into the main branch.
        """
        try:
            token = await self.github.get_installation_token(installation_id)
            repo_full_name = f"{owner}/{repo}"
            
            # Get the file to find its SHA (required for deletion)
            file_data = await self.github.get_repository_content(
                installation_id, owner, repo, KINTSUGI_METADATA_FILE, ref=branch
            )
            
            if not file_data:
                logger.debug(f"No metadata file to clean up on branch '{branch}'")
                return
            
            # Delete the file
            import httpx
            url = f"https://api.github.com/repos/{repo_full_name}/contents/{KINTSUGI_METADATA_FILE}"
            
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    json={
                        "message": "chore(kintsugi): Clean up metadata file",
                        "sha": file_data["sha"],
                        "branch": branch,
                    },
                )
                response.raise_for_status()
            
            logger.info(f"🧹 Cleaned up metadata file from branch '{branch}'")
            
        except Exception as e:
            logger.warning(f"Failed to clean up metadata file: {e}")

    async def _create_file(
        self,
        token: str,
        repo_full_name: str,
        path: str,
        content: str,
        branch: str,
        message: str,
    ):
        """Create a new file in the repository."""
        import httpx
        
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        async with httpx.AsyncClient() as client:
            response = await client.put(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "message": message,
                    "content": encoded_content,
                    "branch": branch,
                },
            )
            response.raise_for_status()

    def _extract_error_summary(self, error_text: str, max_length: int = 500) -> str:
        """Extract a brief summary of the error for tracking."""
        if not error_text:
            return "No error text available"
        
        # Skip truncation markers
        error_text = error_text.replace("... [truncated] ...", "").strip()
        
        # Look for common error patterns (Playwright, Jest, pytest, etc.)
        patterns = [
            r'Error:?\s*(.+?)(?:\n|$)',
            r'AssertionError:?\s*(.+?)(?:\n|$)',
            r'TimeoutError:?\s*(.+?)(?:\n|$)',
            r'expect\(.+?\)\.(.+?)(?:\n|$)',
            r'Locator.+?failed(.+?)(?:\n|$)',
            # Playwright specific patterns
            r'(\d+\)\s+\[chromium\].+?─+.+?)(?:\n|$)',
            r'(Timed out \d+ms waiting for.+?)(?:\n|$)',
            r'(Expected:.+?Received:.+?)(?:\n|$)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, error_text, re.IGNORECASE)
            if match:
                summary = match.group(1).strip()[:max_length]
                return summary
        
        # Fallback: first non-empty line
        for line in error_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('---'):
                return line[:max_length]
        
        return "Unknown error"

    async def _handle_max_attempts_reached(
        self,
        token: str,
        installation_id: int,
        owner: str,
        repo: str,
        repo_full_name: str,
        branch: str,
        run_id: int,
        config: KintsugiConfig,
    ):
        """
        Handle the case when max attempts have been reached without success.
        Opens a PR with a failure report so humans can take over.
        """
        logger.info("🚨 Opening PR with failure report (max attempts exhausted)")
        
        # Check if PR already exists for this branch
        existing_pr = await self._find_pr_for_branch(token, repo_full_name, branch)
        if existing_pr:
            pr_number = existing_pr.get("number")
            pr_url = existing_pr.get("html_url", "N/A")
            logger.info(f"PR #{pr_number} already exists - skipping duplicate PR creation: {pr_url}")
            # Clean up the chat session since we're done
            self.gemini.clear_session(branch)
            return
        
        # Fetch metadata for the report
        metadata = await self._fetch_metadata(installation_id, owner, repo, branch)
        
        if not metadata:
            logger.error("No metadata found for failure report")
            return
        
        # Build failure PR body
        attempts_table = self._build_attempts_table(metadata.attempts)
        evidence_list = self._build_evidence_list(metadata.evidence_used)
        
        pr_body = f"""# 🚨 Kintsugi Auto-Fix - Human Assistance Required

| Metric | Value |
|--------|-------|
| **Status** | ❌ **MAX ATTEMPTS REACHED** |
| **Attempts** | {len(metadata.attempts)}/{config.limits.max_attempts} |
| **Primary File** | `{metadata.primary_file}` |
| **Original Run** | `{metadata.original_run_id}` |

## ⚠️ What Happened

Kintsugi attempted to fix this test **{len(metadata.attempts)} times** but the tests are still failing.
This likely indicates a more complex issue that requires human review.

## 🧠 Last AI Reasoning

<details>
<summary>Click to see Kintsugi's thought process</summary>

{metadata.thought_process}

</details>

## 🛠️ Last Attempted Fix

{metadata.explanation}

## 📊 Attempt History

{attempts_table}

## 📎 Evidence Analyzed

{evidence_list}

---

**Next Steps:**
1. Review the attempted fixes in this branch
2. Check if the issue is environmental (flaky test, CI config)
3. Make manual adjustments if needed
4. Once fixed, Kintsugi can learn from this for future runs

---
*Generated by [Kintsugi](https://github.com/AhmedAbubaker98/Kintsugi) - The Autonomous QA Orchestrator*
"""
        
        pr_response = await self.github.create_pull_request(
            token=token,
            repo_full_name=repo_full_name,
            title=f"🚨 Kintsugi Needs Help: {metadata.primary_file}",
            body=pr_body,
            head=branch,
            base=metadata.base_branch,
        )
        
        pr_url = pr_response.get("html_url", "N/A")
        logger.info(f"🚨 Failure PR opened: {pr_url}")
        
        # Clean up the chat session since we're done with this fix
        self.gemini.clear_session(branch)

    def _build_attempts_table(self, attempts: list[AttemptRecord]) -> str:
        """Build a markdown table of attempts."""
        if not attempts:
            return "*No attempt records available*"
        
        lines = ["| # | Time | Error | Files Changed |", "|---|------|-------|---------------|"]
        for attempt in attempts:
            files = ", ".join(f"`{f}`" for f in attempt.files_changed[:2])
            if len(attempt.files_changed) > 2:
                files += f" +{len(attempt.files_changed) - 2} more"
            lines.append(f"| {attempt.attempt_number} | {attempt.timestamp[:16]} | {attempt.error_summary[:50]}... | {files} |")
        
        return "\n".join(lines)

    def _build_evidence_list(self, evidence: EvidenceUsed) -> str:
        """Build a list of evidence sources used."""
        items = []
        if evidence.screenshot:
            items.append("- 📸 Screenshot of UI at failure")
        if evidence.video:
            items.append("- 🎬 Video recording of test execution")
        if evidence.dom_snapshot:
            items.append("- 🌐 DOM snapshot at failure time")
        if evidence.error_log:
            items.append("- 📋 Error log from CI/CD")
        
        if not items:
            return "*No evidence was available*"
        
        return "\n".join(items)

    async def _extract_evidence(self, zip_content: bytes) -> dict:
        """
        Extract screenshot, video recording, DOM snapshot, and error text from the test report ZIP.
        
        Args:
            zip_content: The downloaded artifact ZIP bytes.
        
        Returns:
            dict: Contains 'screenshot' (bytes), 'video' (bytes), 'dom_snapshot' (str), and 'error_text' (str).
        """
        evidence = {"screenshot": None, "video": None, "dom_snapshot": None, "error_text": ""}
        
        try:
            with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
                file_list = z.namelist()
                logger.info(f"📂 Artifact contents: {len(file_list)} files")

                # Find screenshot
                screenshot_file = next((f for f in file_list if f.endswith(".png")), None)
                if screenshot_file:
                    logger.info(f"📸 Found screenshot: {screenshot_file}")
                    evidence["screenshot"] = z.read(screenshot_file)
                    
                    # Save for debugging
                    os.makedirs("debug_screenshots", exist_ok=True)
                    with open(f"debug_screenshots/{os.path.basename(screenshot_file)}", "wb") as f:
                        f.write(evidence["screenshot"])

                # Find video recording (.webm files from Playwright)
                video_file = next((f for f in file_list if f.endswith(".webm")), None)
                if video_file:
                    logger.info(f"🎬 Found video recording: {video_file}")
                    evidence["video"] = z.read(video_file)
                    
                    # Save for debugging
                    os.makedirs("debug_videos", exist_ok=True)
                    with open(f"debug_videos/{os.path.basename(video_file)}", "wb") as f:
                        f.write(evidence["video"])
                    logger.info(f"🎬 Video size: {len(evidence['video']):,} bytes")

                # Find DOM snapshot (HTML files from Playwright traces or custom snapshots)
                # Look for snapshot.html, dom.html, or files in trace folders
                dom_files = [
                    f for f in file_list 
                    if f.endswith(".html") and any(
                        keyword in f.lower() 
                        for keyword in ["snapshot", "dom", "trace", "page"]
                    )
                ]
                if dom_files:
                    dom_file = dom_files[0]
                    logger.info(f"🌐 Found DOM snapshot: {dom_file}")
                    dom_content = z.read(dom_file).decode("utf-8", errors="ignore")
                    evidence["dom_snapshot"] = dom_content[:50000]  # Limit size
                    
                    # Save for debugging
                    os.makedirs("debug_dom", exist_ok=True)
                    with open(f"debug_dom/{os.path.basename(dom_file)}", "w", encoding="utf-8") as f:
                        f.write(dom_content)
                    logger.info(f"🌐 DOM snapshot size: {len(dom_content):,} chars")

                # Find error text - prioritize .md and .txt files
                error_files = [f for f in file_list if f.endswith(('.md', '.txt', '.log'))]
                if error_files:
                    # Concatenate all error files
                    error_content = []
                    for ef in error_files[:3]:  # Limit to 3 files
                        content = z.read(ef).decode("utf-8", errors="ignore")
                        error_content.append(f"--- {ef} ---\n{content}")
                    evidence["error_text"] = "\n\n".join(error_content)[:10000]
                    logger.info(f"📋 Found {len(error_files)} error file(s)")
                else:
                    # Fallback to HTML or file list
                    html_file = next((f for f in file_list if f.endswith(".html")), None)
                    if html_file:
                        html_content = z.read(html_file).decode("utf-8", errors="ignore")
                        evidence["error_text"] = f"From {html_file}:\n{html_content[:5000]}"
                    else:
                        evidence["error_text"] = f"Artifact files: {', '.join(file_list)}"
                        logger.warning("No error text found, using file list.")

        except Exception as e:
            logger.error(f"Failed to extract evidence: {e}")

        return evidence

    async def _fetch_workflow_logs(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        run_id: int,
    ) -> str:
        """
        Fetch workflow run logs directly from GitHub API.
        
        Used when no artifacts are available to get error context.
        The logs are returned as a ZIP file which we extract.
        
        Args:
            installation_id: GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            run_id: Workflow run ID.
        
        Returns:
            str: Concatenated log content (truncated to reasonable size).
        """
        try:
            logs_zip = await self.github.get_workflow_run_logs(
                installation_id, owner, repo, run_id
            )
            
            if not logs_zip:
                return ""
            
            # Extract logs from ZIP
            log_content = []
            with zipfile.ZipFile(io.BytesIO(logs_zip)) as z:
                file_list = z.namelist()
                logger.debug(f"Workflow logs ZIP contains: {file_list}")
                
                # Sort to process in order (job names are usually numbered)
                for log_file in sorted(file_list):
                    if log_file.endswith('.txt'):
                        try:
                            content = z.read(log_file).decode("utf-8", errors="ignore")
                            # Add file header for context
                            log_content.append(f"--- {log_file} ---\n{content}")
                        except Exception as e:
                            logger.debug(f"Could not read {log_file}: {e}")
            
            # Concatenate and truncate
            full_logs = "\n\n".join(log_content)
            
            # Keep last 15000 chars (usually contains the actual error)
            if len(full_logs) > 15000:
                full_logs = "... [truncated] ...\n" + full_logs[-15000:]
            
            return full_logs
            
        except Exception as e:
            logger.warning(f"Failed to fetch workflow logs: {e}")
            return ""

    async def handle_kintsugi_success(
        self,
        installation_id: int,
        repo_full_name: str,
        branch: str,
    ):
        """
        Handle successful workflow run on a Kintsugi branch.
        THIS IS THE MAGIC MOMENT - Create the PR with the full success report!
        
        Args:
            installation_id: The GitHub App installation ID.
            repo_full_name: Full repository name (owner/repo).
            branch: The Kintsugi branch name.
        """
        try:
            owner, repo = repo_full_name.split("/")
            token = await self.github.get_installation_token(installation_id)
            
            # Load config to check enabled status and cleanup_metadata setting
            config = await self.config_service.get_config(installation_id, owner, repo, ref="main")
            
            # Check if Kintsugi is enabled
            if not config.enabled:
                logger.info(f"⏸️ Kintsugi is disabled for {repo_full_name}. Skipping success handling.")
                return
            
            logger.info(f"🎉 SUCCESS on branch '{branch}'! Creating verified PR...")
            
            # Check if PR already exists (in case of re-runs)
            existing_pr = await self._find_pr_for_branch(token, repo_full_name, branch)
            if existing_pr:
                # PR exists - the detailed PR report already conveys success
                # No need for redundant "All Tests Passing" comments
                pr_number = existing_pr.get("number")
                logger.info(f"PR #{pr_number} already exists - skipping (PR report is sufficient)")
                return
            
            # No PR exists - THIS IS THE MAGIC MOMENT! Create the verified PR
            metadata = await self._fetch_metadata(installation_id, owner, repo, branch)
            
            if not metadata:
                logger.warning(f"No metadata found for branch '{branch}'. Creating basic PR.")
                # Fallback to basic PR
                await self.github.create_pull_request(
                    token=token,
                    repo_full_name=repo_full_name,
                    title=f"✅ Kintsugi Auto-Fix (Verified)",
                    body="Tests are passing! This fix was verified by CI.",
                    head=branch,
                    base="main",
                )
                return
            
            # Build the HIGH-FIDELITY PR report
            pr_body = self._build_success_pr_body(metadata)
            
            pr_response = await self.github.create_pull_request(
                token=token,
                repo_full_name=repo_full_name,
                title=f"✅ Kintsugi Verified Fix: {metadata.primary_file}",
                body=pr_body,
                head=branch,
                base=metadata.base_branch,
            )
            
            pr_url = pr_response.get("html_url", "N/A")
            logger.info(f"🎉 VERIFIED PR OPENED! URL: {pr_url}")
            
            # Clean up metadata file if configured
            if config.cleanup_metadata:
                await self._cleanup_metadata_file(installation_id, owner, repo, branch)
            
            # Clean up the chat session since we're done with this fix
            self.gemini.clear_session(branch)
            
        except Exception as e:
            logger.error(f"❌ Failed to handle Kintsugi success: {e}", exc_info=True)

    def _build_success_pr_body(self, metadata: KintsugiFixMetadata) -> str:
        """Build the high-fidelity PR body for a successful fix."""
        
        # Build evidence list
        evidence_items = []
        if metadata.evidence_used.screenshot:
            evidence_items.append("📸 Screenshot")
        if metadata.evidence_used.video:
            evidence_items.append("🎬 Video")
        if metadata.evidence_used.dom_snapshot:
            evidence_items.append("🌐 DOM")
        if metadata.evidence_used.error_log:
            evidence_items.append("📋 Logs")
        evidence_str = " + ".join(evidence_items) if evidence_items else "Code Only"
        
        # Build attempts summary
        attempts_count = len(metadata.attempts)
        
        # Build the PR body
        pr_body = f"""# ✅ Kintsugi Self-Healing Report

| Metric | Value |
|--------|-------|
| **Status** | ✅ **VERIFIED FIX** (CI Passed) |
| **Attempts** | {attempts_count} iteration(s) |
| **Evidence** | {evidence_str} |
| **Primary File** | `{metadata.primary_file}` |

## 🧠 Thought Process

<details>
<summary>Click to see Kintsugi's AI reasoning</summary>

{metadata.thought_process}

</details>

## 🛠️ The Fix

{metadata.explanation}

"""
        
        # Add attempt history if multiple attempts
        if attempts_count > 1:
            pr_body += f"""## 📊 Iteration History

{self._build_attempts_table(metadata.attempts)}

"""
        
        # Add evidence section
        evidence_list = self._build_evidence_list(metadata.evidence_used)
        pr_body += f"""## 📎 Evidence Analyzed

{evidence_list}

"""
        
        # Footer
        pr_body += """---

**What's Next?**
- Review the changes and merge if satisfied
- Need adjustments? Comment with **@kintsugi-app** and your feedback
- This fix was automatically verified by your CI pipeline

---
*Generated by [Kintsugi](https://github.com/AhmedAbubaker98/Kintsugi) - The Autonomous QA Orchestrator*
Helping developers do more of what they love by automating the tedious parts of development.
"""
        
        return pr_body

    async def _find_pr_for_branch(
        self,
        token: str,
        repo_full_name: str,
        branch: str,
    ) -> dict | None:
        """
        Find an open PR associated with a branch.
        
        Args:
            token: GitHub installation token.
            repo_full_name: Full repository name (owner/repo).
            branch: Branch name to search for.
        
        Returns:
            dict | None: PR data if found, None otherwise.
        """
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.github.com/repos/{repo_full_name}/pulls",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                params={"head": f"{repo_full_name.split('/')[0]}:{branch}", "state": "open"},
            )
            if response.status_code == 200:
                prs = response.json()
                if prs:
                    return prs[0]  # Return the first matching PR
        return None

    async def process_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        comment_body: str,
        comment_author: str,
    ):
        """
        Process a comment mentioning @kintsugi-app and generate amendments.
        
        Args:
            installation_id: The GitHub App installation ID.
            repo_full_name: Full repository name (owner/repo).
            pr_number: The PR number where the comment was made.
            comment_body: The comment text.
            comment_author: GitHub username of the commenter.
        """
        try:
            owner, repo = repo_full_name.split("/")
            token = await self.github.get_installation_token(installation_id)
            
            logger.info(f"🗣️ Processing @kintsugi-app mention on PR #{pr_number} by @{comment_author}")
            
            # 1. Get PR details to find the branch
            pr = await self.github.get_pull_request(installation_id, owner, repo, pr_number)
            head_branch = pr.get("head", {}).get("ref", "")
            base_branch = pr.get("base", {}).get("ref", "main")
            
            # Verify this is a Kintsugi PR
            if not head_branch.startswith("kintsugi-fix"):
                logger.info(f"PR #{pr_number} is not a Kintsugi PR (branch: {head_branch}). Ignoring.")
                return
            
            # 2. Load config
            config = await self.config_service.get_config(installation_id, owner, repo, ref=base_branch)
            
            # 2.5. Check if Kintsugi is enabled
            if not config.enabled:
                logger.info(f"⏸️ Kintsugi is disabled for {repo_full_name}. Skipping comment processing.")
                return
            
            # 3. DEMO PASSWORD VALIDATION (Hackathon protection)
            from app.core.config import settings
            expected_password = settings.judge_password.get_secret_value()
            if expected_password:  # Only validate if server has a password set
                if config.demo_password != expected_password:
                    logger.warning(
                        f"🚫 Invalid or missing demo_password for {repo_full_name}. "
                        "Kintsugi is currently in a restricted demo mode."
                    )
                    return
            
            # 4. Get files changed by Kintsugi in this PR
            changed_files = await self._get_pr_changed_files(token, repo_full_name, pr_number)
            if not changed_files:
                logger.warning("Could not find any changed files in this PR")
                return
            
            logger.info(f"📄 PR has {len(changed_files)} changed file(s): {list(changed_files.keys())}")
            
            # 5. Get repository file structure
            repo_files = await self.github.list_repository_files(token, repo_full_name, ref=head_branch)
            
            # 6. Parse comment for mentioned file paths
            mentioned_files = self._parse_file_mentions(comment_body, repo_files)
            logger.info(f"📝 Files mentioned in comment: {mentioned_files}")
            
            # 7. Fetch context files (imports from changed files + mentioned files)
            context_files = {}
            for file_path, content in changed_files.items():
                file_context = await self._fetch_context_files(
                    installation_id, owner, repo, head_branch,
                    file_path, content, repo_files
                )
                context_files.update(file_context)
            
            # Also fetch mentioned files if not already in changed_files
            for mentioned in mentioned_files:
                if mentioned not in changed_files and mentioned not in context_files:
                    file_data = await self.github.get_repository_content(
                        installation_id, owner, repo, mentioned, ref=head_branch
                    )
                    if file_data:
                        context_files[mentioned] = base64.b64decode(file_data["content"]).decode("utf-8")
            
            logger.info(f"📚 Fetched {len(context_files)} context files")
            
            # 8. Get AI model and thinking budget from config
            model_name = self.config_service.get_model_name(config)
            thinking_budget = self.config_service.get_thinking_budget(config)
            
            # 8. Call Gemini to generate amendments (using Chat API for conversation continuity)
            logger.info("🧠 Sending to Gemini for amendment generation...")
            amendment_result = self.gemini.generate_amendment(
                comment_body=comment_body,
                comment_author=comment_author,
                changed_files=changed_files,
                context_files=context_files,
                mentioned_files=mentioned_files,
                repo_file_structure=repo_files,
                extra_instructions=config.ai.extra_instructions,
                model_name=model_name,
                thinking_budget=thinking_budget,
                session_id=head_branch,  # Use branch name for session continuity
            )
            
            logger.info(f"✨ Gemini generated {len(amendment_result.fixes)} amendment(s)")
            
            # 10. Security scan amendments before applying
            if amendment_result.fixes:
                _, safe_fixes = await self._security_scan_fixes(amendment_result.fixes, config)
                
                # 11. Apply the safe amendments (commit to the same branch)
                for fix in safe_fixes:
                    # Check protected paths
                    if self.config_service.is_path_protected(config, fix.file_path):
                        logger.warning(f"🛡️ Skipping protected file: {fix.file_path}")
                        continue
                    
                    await self._apply_fix(
                        token, installation_id, owner, repo, repo_full_name,
                        head_branch, fix.file_path, fix.content,
                        f"Kintsugi amendment per @{comment_author}'s feedback"
                    )
            
            # 12. Post reply comment
            reply_body = f"{amendment_result.reply}\n\n---\n* Kintsugi - Self-Healing Test Bot*"
            await self.github.create_pr_comment(
                installation_id=installation_id,
                owner=owner,
                repo=repo,
                pull_number=pr_number,
                body=reply_body,
            )
            
            logger.info(f"✅ Posted amendment reply on PR #{pr_number}")
            
        except Exception as e:
            logger.error(f"❌ Failed to process comment: {e}", exc_info=True)

    async def _get_pr_changed_files(
        self,
        token: str,
        repo_full_name: str,
        pr_number: int,
    ) -> dict[str, str]:
        """
        Get all files changed in a PR with their current content.
        
        Args:
            token: GitHub installation token.
            repo_full_name: Full repository name (owner/repo).
            pr_number: The PR number.
        
        Returns:
            dict: Mapping of file paths to their content.
        """
        import httpx
        
        changed_files = {}
        owner, repo = repo_full_name.split("/")
        
        try:
            async with httpx.AsyncClient() as client:
                # Get list of files changed in PR
                response = await client.get(
                    f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                response.raise_for_status()
                files = response.json()
                
                # Fetch content for each file
                for file_info in files:
                    file_path = file_info.get("filename")
                    if file_path and file_info.get("status") != "removed":
                        # Get file content from the PR's head branch
                        content_response = await client.get(
                            file_info.get("contents_url"),
                            headers={
                                "Authorization": f"Bearer {token}",
                                "Accept": "application/vnd.github+json",
                            },
                        )
                        if content_response.status_code == 200:
                            content_data = content_response.json()
                            content = base64.b64decode(content_data.get("content", "")).decode("utf-8")
                            changed_files[file_path] = content
        
        except Exception as e:
            logger.error(f"Failed to get PR changed files: {e}")
        
        return changed_files

    def _parse_file_mentions(self, comment_body: str, repo_files: list[str]) -> list[str]:
        """
        Parse a comment for mentioned file paths or directories.
        
        Args:
            comment_body: The comment text.
            repo_files: List of all files in the repository.
        
        Returns:
            list: File paths mentioned in the comment that exist in the repo.
        """
        mentioned = []
        
        # Common patterns for file mentions
        patterns = [
            # Explicit paths: "check src/pages/login.ts" or "look at tests/e2e/auth.spec.ts"
            r'(?:check|look at|see|update|fix|modify|change|in|at|file)\s+[`"\']?([a-zA-Z0-9_\-./]+\.[a-zA-Z]+)[`"\']?',
            # Backtick wrapped: `src/utils/helper.ts`
            r'`([a-zA-Z0-9_\-./]+\.[a-zA-Z]+)`',
            # Just paths that look like files (with extension)
            r'\b([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-./]+\.[a-zA-Z]{2,4})\b',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, comment_body, re.IGNORECASE)
            for match in matches:
                # Check if this file exists in the repo
                if match in repo_files:
                    if match not in mentioned:
                        mentioned.append(match)
                else:
                    # Try to find partial matches (e.g., "login.ts" might match "src/pages/login.ts")
                    for repo_file in repo_files:
                        if repo_file.endswith(match) or match in repo_file:
                            if repo_file not in mentioned:
                                mentioned.append(repo_file)
                                break
        
        return mentioned