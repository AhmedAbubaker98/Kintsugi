import logging
import zipfile
import io
import os
import asyncio
import base64
import time
import re
from pathlib import PurePosixPath
from app.services.github_service import GitHubService
from app.services.gemini_service import GeminiService
from app.services.config_service import ConfigService
from app.schemas.config import KintsugiConfig

logger = logging.getLogger(__name__)

# Common test file patterns for different frameworks
FILE_PATTERNS = [
    # Playwright
    r'(?:at\s+)?([^\s:]+\.spec\.[jt]sx?)',
    r'(?:at\s+)?([^\s:]+\.test\.[jt]sx?)',
    # Cypress
    r'(?:at\s+)?([^\s:]+\.cy\.[jt]sx?)',
    # Python pytest
    r'(?:File\s+["\'])?([^\s:"\']+test[^\s:"\']*\.py)',
    r'(?:File\s+["\'])?([^\s:"\']+_test\.py)',
    # Generic paths in errors
    r'(?:in\s+|at\s+|from\s+)([^\s:()]+/tests?/[^\s:()]+\.[jt]sx?)',
    r'(?:in\s+|at\s+|from\s+)([^\s:()]+/e2e/[^\s:()]+\.[jt]sx?)',
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

    async def process_failure(self, installation_id: int, repo_full_name: str, run_id: int, branch: str = "main"):
        """
        Orchestrates the full self-healing pipeline:
        Auth -> Load Config -> Extract Evidence -> Identify Files -> Fetch Context -> AI Analysis -> Commit Fix
        """
        try:
            # 1. Authenticate as the App
            token = await self.github.get_installation_token(installation_id)
            logger.info(f"🔐 Authenticated for repo {repo_full_name}")
            owner, repo = repo_full_name.split("/")

            # 2. Load Repository Configuration
            config = await self.config_service.get_config(installation_id, owner, repo, ref=branch)
            
            # 3. Check if branch is allowed
            if not self.config_service.is_branch_allowed(config, branch):
                logger.info(f"⏭️ Branch '{branch}' is not in allowed list. Skipping.")
                return

            # 4. Download Artifacts (if available)
            artifacts = await self._get_artifacts_with_retry(token, repo_full_name, run_id)
            
            # Initialize evidence with defaults
            evidence = {"screenshot": None, "error_text": "No artifact error log available."}
            broken_file_path = None
            
            if artifacts:
                # Find test-related artifacts (flexible pattern matching)
                target_artifact = next(
                    (a for a in artifacts if any(
                        keyword in a["name"].lower() 
                        for keyword in ["report", "results", "test", "playwright", "cypress", "jest", "pytest"]
                    )),
                    None
                )
                
                if target_artifact:
                    logger.info(f"📦 Found Artifact: {target_artifact['name']} (ID: {target_artifact['id']})")
                    zip_content = await self.github.download_artifact(installation_id, owner, repo, target_artifact["id"])
                    
                    # 3. Extract Evidence (screenshot + error log)
                    evidence = await self._extract_evidence(zip_content)
                    
                    # 4. Dynamic File Discovery - Identify broken file from error log
                    broken_file_path = self._identify_broken_file(evidence["error_text"])
                else:
                    logger.warning("No test report artifact found in artifacts list.")
            else:
                logger.warning(f"No artifacts found for run {run_id}. Will attempt to continue with defaults.")
            
            # 5. Get repository file structure for context (needed for fallback discovery)
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

            # 6. Fetch the broken file content (with fallback to main if branch doesn't exist)
            file_data = await self.github.get_repository_content(
                installation_id, owner, repo, broken_file_path, ref=fetch_branch
            )
            
            # If branch doesn't exist (deleted kintsugi branch), fall back to main
            if not file_data and branch.startswith("kintsugi-fix"):
                logger.warning(f"Branch '{branch}' not found, falling back to 'main'")
                fetch_branch = "main"
                branch = "main"  # Reset branch for subsequent operations
                # Re-fetch repo files from the correct branch
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

            # 9. Call Gemini with full context
            logger.info("🧠 Sending to Gemini with full context...")
            
            # Get AI model based on config
            model_name = self.config_service.get_model_name(config)
            logger.info(f"🤖 Using AI model: {model_name} (mode: {config.ai.mode})")
            
            fix_result = self.gemini.generate_fix(
                primary_file_path=broken_file_path,
                primary_file_content=broken_file_content,
                error_log=evidence["error_text"],
                screenshot_bytes=evidence["screenshot"],
                context_files=context_files,
                repo_file_structure=repo_files,
                extra_instructions=config.ai.extra_instructions,
                model_name=model_name,
            )

            logger.info("✨ KINTSUGI FIX GENERATED ✨")
            logger.info(f"📝 {fix_result.explanation}")
            logger.info(f"📄 {len(fix_result.fixes)} file(s) to update")

            # 10. Validate fixes against config limits
            if len(fix_result.fixes) > config.limits.max_files_changed:
                logger.warning(
                    f"⚠️ Gemini suggested {len(fix_result.fixes)} files, "
                    f"but config limits to {config.limits.max_files_changed}. Truncating."
                )
                fix_result.fixes = fix_result.fixes[:config.limits.max_files_changed]

            # 11. Check for protected files
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

            # 12. Iterative Branching Strategy
            target_branch, base_branch, is_new_branch = await self._determine_branch_strategy(
                token, repo_full_name, branch, installation_id, owner, repo
            )

            # 13. Apply allowed fixes only
            for fix in allowed_fixes:
                await self._apply_fix(
                    token, installation_id, owner, repo, repo_full_name,
                    target_branch, fix.file_path, fix.content, fix_result.explanation
                )

            # 14. Open PR only if we created a new branch
            if is_new_branch:
                await self._open_pull_request(
                    token, repo_full_name, target_branch, base_branch,
                    broken_file_path, run_id, fix_result.explanation
                )
            else:
                logger.info(f"🔄 Iterative fix pushed to existing branch '{target_branch}'")

        except Exception as e:
            logger.error(f"❌ Error processing failure: {e}", exc_info=True)

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

    async def _open_pull_request(
        self,
        token: str,
        repo_full_name: str,
        head_branch: str,
        base_branch: str,
        primary_file: str,
        run_id: int,
        explanation: str,
    ):
        """Open a pull request for the fix."""
        logger.info("🔀 Opening Pull Request...")
        
        pr_body = f"""## Kintsugi Auto-Fix

**Run ID:** `{run_id}`
**Primary File:** `{primary_file}`

### What was wrong:
{explanation}

### Evidence analyzed:
- 📸 Screenshot of UI at failure
- 📋 Error log from CI/CD
- 📄 Test code and imported dependencies
- 🗂️ Repository file structure

---
*Generated automatically by [Kintsugi](https://github.com/AhmedAbubaker98/Kintsugi) - The Software Engineer Bot at your Side*
"""
        
        pr_response = await self.github.create_pull_request(
            token=token,
            repo_full_name=repo_full_name,
            title=f"🚑 Kintsugi Auto-Fix: {primary_file}",
            body=pr_body,
            head=head_branch,
            base=base_branch,
        )
        
        pr_url = pr_response.get("html_url", "N/A")
        logger.info(f"✅ PR OPENED! URL: {pr_url}")

    async def _extract_evidence(self, zip_content: bytes) -> dict:
        """
        Extract screenshot and error text from the test report ZIP.
        
        Args:
            zip_content: The downloaded artifact ZIP bytes.
        
        Returns:
            dict: Contains 'screenshot' (bytes) and 'error_text' (str).
        """
        evidence = {"screenshot": None, "error_text": ""}
        
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

    async def handle_kintsugi_success(
        self,
        installation_id: int,
        repo_full_name: str,
        branch: str,
    ):
        """
        Handle successful workflow run on a Kintsugi branch.
        Posts a success comment on the associated PR.
        
        Args:
            installation_id: The GitHub App installation ID.
            repo_full_name: Full repository name (owner/repo).
            branch: The Kintsugi branch name.
        """
        try:
            owner, repo = repo_full_name.split("/")
            token = await self.github.get_installation_token(installation_id)
            
            # Find the PR associated with this branch
            pr = await self._find_pr_for_branch(token, repo_full_name, branch)
            if not pr:
                logger.warning(f"No open PR found for branch '{branch}'. Cannot post success comment.")
                return
            
            pr_number = pr.get("number")
            
            # Post success comment
            success_comment = (
                "## ✅ Tests Passed!\n\n"
                "Great news! All tests are now passing on this branch. 🎉\n\n"
                "If you need any further amendments, just mention me with **@Kintsugi** "
                "and describe what you'd like changed.\n\n"
                "---\n"
                "* Kintsugi - Self-Healing Test Bot*"
            )
            
            await self.github.create_pr_comment(
                installation_id=installation_id,
                owner=owner,
                repo=repo,
                pull_number=pr_number,
                body=success_comment,
            )
            
            logger.info(f"✅ Posted success comment on PR #{pr_number}")
            
        except Exception as e:
            logger.error(f"❌ Failed to handle Kintsugi success: {e}", exc_info=True)

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
        Process a comment mentioning @Kintsugi and generate amendments.
        
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
            
            logger.info(f"🗣️ Processing @Kintsugi mention on PR #{pr_number} by @{comment_author}")
            
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
            
            # 3. Get files changed by Kintsugi in this PR
            changed_files = await self._get_pr_changed_files(token, repo_full_name, pr_number)
            if not changed_files:
                logger.warning("Could not find any changed files in this PR")
                return
            
            logger.info(f"📄 PR has {len(changed_files)} changed file(s): {list(changed_files.keys())}")
            
            # 4. Get repository file structure
            repo_files = await self.github.list_repository_files(token, repo_full_name, ref=head_branch)
            
            # 5. Parse comment for mentioned file paths
            mentioned_files = self._parse_file_mentions(comment_body, repo_files)
            logger.info(f"📝 Files mentioned in comment: {mentioned_files}")
            
            # 6. Fetch context files (imports from changed files + mentioned files)
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
            
            # 7. Get AI model from config
            model_name = self.config_service.get_model_name(config)
            
            # 8. Call Gemini to generate amendments
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
            )
            
            logger.info(f"✨ Gemini generated {len(amendment_result.fixes)} amendment(s)")
            
            # 9. Apply the amendments (commit to the same branch)
            if amendment_result.fixes:
                for fix in amendment_result.fixes:
                    # Check protected paths
                    if self.config_service.is_path_protected(config, fix.file_path):
                        logger.warning(f"🛡️ Skipping protected file: {fix.file_path}")
                        continue
                    
                    await self._apply_fix(
                        token, installation_id, owner, repo, repo_full_name,
                        head_branch, fix.file_path, fix.content,
                        f"Kintsugi amendment per @{comment_author}'s feedback"
                    )
            
            # 10. Post reply comment
            reply_body = f"{amendment_result.reply}\n\n---\n*🤖 Kintsugi - Self-Healing Test Bot*"
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