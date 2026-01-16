"""
GitHub Service for interacting with the GitHub API.

This service handles:
- GitHub App authentication (JWT and Installation tokens)
- Repository operations (fetching files, diffs, artifacts)
- Pull Request operations (comments, commits)
"""

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
            dict: The file content and metadata.
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
