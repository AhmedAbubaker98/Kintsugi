"""
GitHub Service for interacting with the GitHub API.

This service handles:
- GitHub App authentication (JWT and Installation tokens)
- Repository operations (fetching files, diffs, artifacts)
- Pull Request operations (comments, commits)
"""

import base64
import logging
import time
from datetime import datetime
from typing import Any, Optional

import httpx
import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)


class GitHubService:
    """
    Service for interacting with GitHub API as a GitHub App.
    
    This service manages authentication using GitHub App credentials
    and provides methods for common GitHub operations needed by Kintsugi.
    
    Attributes:
        app_id: The GitHub App ID.
        private_key: The GitHub App private key.
        base_url: The GitHub API base URL.
    """
    
    def __init__(
        self,
        app_id: Optional[str] = None,
        private_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        """
        Initialize the GitHub service.
        
        Args:
            app_id: GitHub App ID. Defaults to settings value.
            private_key: GitHub App private key. Defaults to settings value.
            base_url: GitHub API base URL. Defaults to settings value.
        """
        self.app_id = app_id or settings.github_app_id
        self.private_key = private_key or settings.github_private_key.get_secret_value()
        self.base_url = base_url or settings.github_api_base_url
        
        # Cache for installation tokens
        self._token_cache: dict[int, dict[str, Any]] = {}

    def _iso_to_epoch(self, value: str) -> float:
        """Convert GitHub ISO8601 timestamp to epoch seconds."""
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

    def _build_headers(self, token: str, accept: Optional[str] = None) -> dict[str, str]:
        """Build standard GitHub API headers."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": accept or "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        return headers

    def _install_headers(self, installation_token: str, accept: Optional[str] = None) -> dict[str, str]:
        """Headers for installation-scoped requests."""
        return self._build_headers(installation_token, accept)
    
    async def get_app_jwt(self) -> str:
        """
        Generate a JSON Web Token (JWT) for GitHub App authentication.
        
        The JWT is used to authenticate as the GitHub App itself,
        which is required for getting installation access tokens.
        
        Returns:
            str: The generated JWT token.
        
        Note:
            JWTs are valid for up to 10 minutes.
        """
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": self.app_id,
        }
        logger.debug("Generating GitHub App JWT")
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    async def list_workflow_artifacts(self, token: str, repo_full_name: str, run_id: int) -> dict:
        """
        Lists all artifacts for a specific workflow run.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/actions/runs/{run_id}/artifacts"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        
    async def get_installation_token(self, installation_id: int) -> str:
        """
        Get an installation access token for a specific installation.
        
        Installation tokens are used to authenticate API requests
        on behalf of a specific installation (repository/organization).
        
        Args:
            installation_id: The GitHub App installation ID.
        
        Returns:
            str: The installation access token.
        
        Note:
            Tokens are cached and reused until they expire.
        """
        # Check cache first
        cached = self._token_cache.get(installation_id)
        if cached and cached["expires_at"] > time.time():
            logger.debug(f"Using cached token for installation {installation_id}")
            return cached["token"]
        
        logger.debug(f"Getting installation token for {installation_id}")
        app_jwt = await self.get_app_jwt()
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/app/installations/{installation_id}/access_tokens",
                headers=self._build_headers(app_jwt),
            )
            response.raise_for_status()
            data = response.json()
            expires_at = self._iso_to_epoch(data["expires_at"])
            self._token_cache[installation_id] = {
                "token": data["token"],
                "expires_at": expires_at,
            }
            return data["token"]
    
    async def get_repository_content(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        path: str,
        ref: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Get the contents of a file or directory from a repository.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner (user or organization).
            repo: Repository name.
            path: Path to the file or directory.
            ref: Git reference (branch, tag, or commit SHA).
        
        Returns:
            dict | None: The file content and metadata, or None if not found.
        """
        logger.debug(f"Fetching content: {owner}/{repo}/{path}@{ref}")
        token = await self.get_installation_token(installation_id)
        params = {"ref": ref} if ref else None
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/contents/{path}",
                headers=self._install_headers(token),
                params=params,
            )
            if response.status_code == 404:
                logger.warning(f"File not found: {owner}/{repo}/{path}@{ref}")
                return None
            response.raise_for_status()
            return response.json()
    
    async def get_pr_diff(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pull_number: int,
    ) -> str:
        """
        Get the diff for a pull request.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            pull_number: Pull request number.
        
        Returns:
            str: The diff in unified diff format.
        """
        logger.debug(f"Fetching PR diff: {owner}/{repo}#{pull_number}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}",
                headers=self._install_headers(token, "application/vnd.github.diff"),
            )
            response.raise_for_status()
            return response.text
    
    async def get_workflow_run_artifacts(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        run_id: int,
    ) -> list[dict[str, Any]]:
        """
        List artifacts for a workflow run.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            run_id: Workflow run ID.
        
        Returns:
            list: List of artifact metadata dictionaries.
        """
        logger.debug(f"Listing artifacts for run: {owner}/{repo}/runs/{run_id}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
                headers=self._install_headers(token),
            )
            response.raise_for_status()
            data = response.json()
            return data.get("artifacts", [])
    
    async def download_artifact(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        artifact_id: int,
    ) -> bytes:
        """
        Download an artifact ZIP file.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            artifact_id: The artifact ID.
        
        Returns:
            bytes: The artifact ZIP file contents.
        """
        logger.debug(f"Downloading artifact: {owner}/{repo}/artifacts/{artifact_id}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
                headers=self._install_headers(token, "application/vnd.github+json"),
            )
            response.raise_for_status()
            return response.content
    
    async def get_workflow_run_logs(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        run_id: int,
    ) -> bytes:
        """
        Download logs for a workflow run.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            run_id: Workflow run ID.
        
        Returns:
            bytes: The logs ZIP file contents.
        """
        logger.debug(f"Downloading logs for run: {owner}/{repo}/runs/{run_id}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/logs",
                headers=self._install_headers(token, "application/vnd.github+json"),
            )
            response.raise_for_status()
            return response.content
    
    async def create_commit(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        branch: str,
        message: str,
        files: dict[str, str],
        parent_sha: str,
    ) -> dict[str, Any]:
        """
        Create a commit with multiple file changes.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            branch: Target branch name.
            message: Commit message.
            files: Dictionary mapping file paths to their new content.
            parent_sha: SHA of the parent commit.
        
        Returns:
            dict: The created commit metadata.
        """
        logger.debug(f"Creating commit on {owner}/{repo}:{branch}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            # Get parent commit to obtain tree
            commit_resp = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/git/commits/{parent_sha}",
                headers=self._install_headers(token),
            )
            commit_resp.raise_for_status()
            parent_commit = commit_resp.json()
            base_tree = parent_commit["tree"]["sha"]

            # Create blobs
            tree_items = []
            for file_path, content in files.items():
                blob_resp = await client.post(
                    f"{self.base_url}/repos/{owner}/{repo}/git/blobs",
                    headers=self._install_headers(token),
                    json={"content": content, "encoding": "utf-8"},
                )
                blob_resp.raise_for_status()
                blob_sha = blob_resp.json()["sha"]
                tree_items.append(
                    {
                        "path": file_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_sha,
                    }
                )

            # Create tree
            tree_resp = await client.post(
                f"{self.base_url}/repos/{owner}/{repo}/git/trees",
                headers=self._install_headers(token),
                json={"base_tree": base_tree, "tree": tree_items},
            )
            tree_resp.raise_for_status()
            tree_sha = tree_resp.json()["sha"]

            # Create commit
            commit_create_resp = await client.post(
                f"{self.base_url}/repos/{owner}/{repo}/git/commits",
                headers=self._install_headers(token),
                json={
                    "message": message,
                    "tree": tree_sha,
                    "parents": [parent_sha],
                },
            )
            commit_create_resp.raise_for_status()
            commit_data = commit_create_resp.json()
            new_sha = commit_data["sha"]

            # Update ref
            ref_resp = await client.patch(
                f"{self.base_url}/repos/{owner}/{repo}/git/refs/heads/{branch}",
                headers=self._install_headers(token),
                json={"sha": new_sha, "force": False},
            )
            ref_resp.raise_for_status()
            return commit_data
    
    async def push_commit(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        branch: str,
        message: str,
        files: dict[str, str],
    ) -> dict[str, Any]:
        """
        Push a commit with file changes to a branch.
        
        This is a higher-level method that handles getting the
        current branch SHA and creating the commit.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            branch: Target branch name.
            message: Commit message.
            files: Dictionary mapping file paths to their new content.
        
        Returns:
            dict: The created commit metadata.
        """
        logger.debug(f"Pushing commit to {owner}/{repo}:{branch}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            ref_resp = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/git/refs/heads/{branch}",
                headers=self._install_headers(token),
            )
            ref_resp.raise_for_status()
            ref_data = ref_resp.json()
            parent_sha = ref_data["object"]["sha"]

        return await self.create_commit(
            installation_id=installation_id,
            owner=owner,
            repo=repo,
            branch=branch,
            message=message,
            files=files,
            parent_sha=parent_sha,
        )
    
    async def create_pr_comment(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
    ) -> dict[str, Any]:
        """
        Create a comment on a pull request.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            pull_number: Pull request number.
            body: Comment body (Markdown supported).
        
        Returns:
            dict: The created comment metadata.
        """
        logger.debug(f"Creating comment on {owner}/{repo}#{pull_number}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/repos/{owner}/{repo}/issues/{pull_number}/comments",
                headers=self._install_headers(token),
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()
    
    async def update_pr_comment(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        comment_id: int,
        body: str,
    ) -> dict[str, Any]:
        """
        Update an existing comment on a pull request.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            comment_id: The ID of the comment to update.
            body: New comment body (Markdown supported).
        
        Returns:
            dict: The updated comment metadata.
        """
        logger.debug(f"Updating comment {comment_id} on {owner}/{repo}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/repos/{owner}/{repo}/issues/comments/{comment_id}",
                headers=self._install_headers(token),
                json={"body": body},
            )
            response.raise_for_status()
            return response.json()
    
    async def get_pull_request(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pull_number: int,
    ) -> dict[str, Any]:
        """
        Get pull request details.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            pull_number: Pull request number.
        
        Returns:
            dict: Pull request metadata.
        """
        logger.debug(f"Fetching PR: {owner}/{repo}#{pull_number}")
        token = await self.get_installation_token(installation_id)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}",
                headers=self._install_headers(token),
            )
            response.raise_for_status()
            return response.json()

    async def update_pull_request(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        pull_number: int,
        title: Optional[str] = None,
        body: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Update a pull request's title or body.
        
        Args:
            installation_id: The GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            pull_number: Pull request number.
            title: New PR title (optional).
            body: New PR body (optional).
        
        Returns:
            dict: Updated pull request metadata.
        """
        logger.debug(f"Updating PR: {owner}/{repo}#{pull_number}")
        token = await self.get_installation_token(installation_id)
        
        payload = {}
        if title is not None:
            payload["title"] = title
        if body is not None:
            payload["body"] = body
        
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}",
                headers=self._install_headers(token),
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    async def update_file(
        self,
        token: str,
        repo_full_name: str,
        path: str,
        message: str,
        content: str,
        sha: str,
        branch: str = "main"
    ) -> dict[str, Any]:
        """
        Commits a file update to GitHub.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            path: Path to the file in the repository.
            message: Commit message.
            content: New file content (will be Base64 encoded).
            sha: Current file SHA (for conflict detection).
            branch: Target branch name.
        
        Returns:
            dict: Commit response from GitHub API.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/contents/{path}"
        headers = self._install_headers(token)
        
        # GitHub API expects content to be Base64 encoded
        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        
        payload = {
            "message": message,
            "content": encoded_content,
            "sha": sha,
            "branch": branch
        }

        logger.debug(f"Updating file: {repo_full_name}/{path} on branch {branch}")
        async with httpx.AsyncClient() as client:
            response = await client.put(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()

    async def get_branch_sha(
        self,
        token: str,
        repo_full_name: str,
        branch: str
    ) -> str:
        """
        Get the latest commit SHA for a branch.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            branch: Branch name.
        
        Returns:
            str: The SHA of the latest commit on the branch.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/git/ref/heads/{branch}"
        headers = self._install_headers(token)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["object"]["sha"]

    async def create_branch(
        self,
        token: str,
        repo_full_name: str,
        new_branch_name: str,
        source_sha: str
    ) -> dict[str, Any]:
        """
        Creates a new git branch (reference) from a source commit SHA.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            new_branch_name: Name for the new branch.
            source_sha: SHA of the commit to branch from.
        
        Returns:
            dict: Reference creation response from GitHub API.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/git/refs"
        headers = self._install_headers(token)
        
        payload = {
            "ref": f"refs/heads/{new_branch_name}",
            "sha": source_sha
        }

        logger.debug(f"Creating branch: {new_branch_name} from {source_sha[:8]}")
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()

    async def create_pull_request(
        self,
        token: str,
        repo_full_name: str,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool = False,
    ) -> dict[str, Any]:
        """
        Opens a Pull Request.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            title: PR title.
            body: PR description/body.
            head: Source branch (the branch with changes).
            base: Target branch (where changes will be merged).
            draft: If True, create as a draft PR.
        
        Returns:
            dict: Pull request creation response from GitHub API.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/pulls"
        headers = self._install_headers(token)
        
        payload = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "draft": draft,
        }

        logger.debug(f"Creating PR: {head} -> {base} (draft={draft})")
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()

    async def list_repository_files(
        self,
        token: str,
        repo_full_name: str,
        ref: Optional[str] = None,
        path: str = ""
    ) -> list[str]:
        """
        List all files in a repository using the Git Trees API.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            ref: Git reference (branch, tag, or commit SHA). Defaults to default branch.
            path: Optional path prefix to filter results.
        
        Returns:
            list[str]: List of file paths in the repository.
        """
        # First get the tree SHA for the ref
        ref = ref or "HEAD"
        url = f"{self.base_url}/repos/{repo_full_name}/git/trees/{ref}?recursive=1"
        headers = self._install_headers(token)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
        # Filter to only files (blobs), not directories (trees)
        files = [
            item["path"] for item in data.get("tree", [])
            if item["type"] == "blob"
        ]
        
        # Filter by path prefix if provided
        if path:
            files = [f for f in files if f.startswith(path)]
            
        return files

    async def check_branch_exists(
        self,
        token: str,
        repo_full_name: str,
        branch: str
    ) -> bool:
        """
        Check if a branch exists in the repository.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            branch: Branch name to check.
        
        Returns:
            bool: True if branch exists, False otherwise.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/git/ref/heads/{branch}"
        headers = self._install_headers(token)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            return response.status_code == 200

    async def get_commits_on_branch(
        self,
        token: str,
        repo_full_name: str,
        branch: str,
        base_branch: str = "main",
    ) -> list[dict]:
        """
        Get commits on a branch that are not on the base branch.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            branch: The branch to get commits from.
            base_branch: The base branch to compare against.
        
        Returns:
            list[dict]: List of commit objects with sha, message, author, etc.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/compare/{base_branch}...{branch}"
        headers = self._install_headers(token)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                logger.warning(f"Could not compare {base_branch}...{branch}")
                return []
            response.raise_for_status()
            data = response.json()
            return data.get("commits", [])

    async def get_branch_commit_count(
        self,
        token: str,
        repo_full_name: str,
        branch: str,
        base_branch: str = "main",
    ) -> int:
        """
        Count commits on a branch ahead of the base branch.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            branch: The branch to count commits on.
            base_branch: The base branch to compare against.
        
        Returns:
            int: Number of commits ahead of base branch.
        """
        commits = await self.get_commits_on_branch(token, repo_full_name, branch, base_branch)
        return len(commits)

    async def get_latest_commit_message(
        self,
        token: str,
        repo_full_name: str,
        branch: str,
    ) -> str:
        """
        Get the latest commit message on a branch.
        
        Args:
            token: Installation access token.
            repo_full_name: Full repository name (owner/repo).
            branch: The branch to get the commit from.
        
        Returns:
            str: The commit message.
        """
        url = f"{self.base_url}/repos/{repo_full_name}/commits/{branch}"
        headers = self._install_headers(token)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data.get("commit", {}).get("message", "")
