"""
Configuration Service for Kintsugi.

Fetches and validates .github/kintsugi.yml from repositories.
Falls back to sensible defaults if config is missing or invalid.
"""

import logging
import base64
import fnmatch
import yaml
from app.services.github_service import GitHubService
from app.schemas.config import KintsugiConfig

logger = logging.getLogger(__name__)


class ConfigService:
    """
    Service for loading and validating Kintsugi configuration.
    
    Looks for .github/kintsugi.yml in the target repository.
    If not found or invalid, returns default configuration.
    """
    
    CONFIG_PATH = ".github/kintsugi.yml"
    
    def __init__(self, github_service: GitHubService):
        self.github = github_service

    async def get_config(
        self,
        installation_id: int,
        owner: str,
        repo: str,
        ref: str = "main"
    ) -> KintsugiConfig:
        """
        Fetches, parses, and validates the config.
        Returns default config if file is missing or invalid.
        
        Args:
            installation_id: GitHub App installation ID.
            owner: Repository owner.
            repo: Repository name.
            ref: Git reference (branch/tag/SHA).
        
        Returns:
            KintsugiConfig: Validated configuration object.
        """
        try:
            # 1. Fetch file from GitHub
            file_data = await self.github.get_repository_content(
                installation_id=installation_id,
                owner=owner,
                repo=repo,
                path=self.CONFIG_PATH,
                ref=ref
            )

            if not file_data:
                logger.info(f"No config found at {self.CONFIG_PATH}. Using defaults.")
                return KintsugiConfig()

            # 2. Decode content
            content = base64.b64decode(file_data["content"]).decode("utf-8")
            
            # 3. Parse YAML
            raw_config = yaml.safe_load(content)
            
            if not raw_config:
                logger.warning("Config file is empty. Using defaults.")
                return KintsugiConfig()
            
            # 4. Validate with Pydantic (merges user config with defaults)
            config = KintsugiConfig(**raw_config)
            
            logger.info(f"✅ Loaded custom config for {owner}/{repo}")
            logger.debug(f"Config: branches.allow={config.branches.allow}, ai.mode={config.ai.mode}")
            return config

        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML in config for {owner}/{repo}: {e}. Using defaults.")
            return KintsugiConfig()
        except Exception as e:
            logger.warning(f"Error loading config for {owner}/{repo}: {e}. Using defaults.")
            return KintsugiConfig()

    def is_branch_allowed(self, config: KintsugiConfig, branch: str) -> bool:
        """
        Check if a branch is allowed based on config rules.
        
        Args:
            config: The loaded configuration.
            branch: Branch name to check.
        
        Returns:
            bool: True if branch is allowed, False otherwise.
        """
        # First check if branch matches any ignore patterns
        for pattern in config.branches.ignore:
            if fnmatch.fnmatch(branch, pattern):
                logger.debug(f"Branch '{branch}' matches ignore pattern '{pattern}'")
                return False
        
        # Then check if it matches any allow patterns
        for pattern in config.branches.allow:
            if fnmatch.fnmatch(branch, pattern):
                logger.debug(f"Branch '{branch}' matches allow pattern '{pattern}'")
                return True
        
        # Default: not in allow list = not allowed
        logger.debug(f"Branch '{branch}' not in allow list")
        return False

    def is_path_protected(self, config: KintsugiConfig, file_path: str) -> bool:
        """
        Check if a file path is protected from modification.
        
        Args:
            config: The loaded configuration.
            file_path: File path to check.
        
        Returns:
            bool: True if file is protected, False otherwise.
        """
        for pattern in config.security.protected_paths:
            if fnmatch.fnmatch(file_path, pattern):
                logger.debug(f"Path '{file_path}' matches protected pattern '{pattern}'")
                return True
        return False

    def get_model_name(self, config: KintsugiConfig) -> str:
        """
        Get the Gemini model name based on AI mode config.
        
        Args:
            config: The loaded configuration.
        
        Returns:
            str: Model name to use.
        """
        if config.ai.mode == "fast":
            return "gemini-flash-latest"
        else:  # "smart" or default
            return "gemini-3-pro-preview"
