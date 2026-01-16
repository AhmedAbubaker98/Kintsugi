import logging
import zipfile
import io
import os
import asyncio
from app.services.github_service import GitHubService

logger = logging.getLogger(__name__)

class WorkflowProcessor:
    def __init__(self):
        self.github = GitHubService()

    async def process_failure(self, installation_id: int, repo_full_name: str, run_id: int):
        """
        Orchestrates the forensics: Auth -> Find Artifact -> Download -> Extract.
        """
        try:
            # 1. Authenticate as the App
            token = await self.github.get_installation_token(installation_id)
            logger.info(f"🔐 Authenticated for repo {repo_full_name}")

            # 2. List Artifacts (With Retry)
            artifacts = []
            for attempt in range(3):
                artifacts_data = await self.github.list_workflow_artifacts(token, repo_full_name, run_id)
                artifacts = artifacts_data.get("artifacts", [])
                
                if artifacts:
                    break
                
                logger.info(f"artifacts list empty, retrying in 2s (Attempt {attempt+1}/3)...")
                await asyncio.sleep(2)
            
            if not artifacts:
                logger.warning(f"No artifacts found for run {run_id} after retries")
                return

            # 3. Find the Playwright Report
            target_artifact = None
            for art in artifacts:
                if "playwright-report" in art["name"]:
                    target_artifact = art
                    break
            
            if not target_artifact:
                logger.info("Playwright report not found in artifacts.")
                return

            logger.info(f"📦 Found Artifact: {target_artifact['name']} (ID: {target_artifact['id']})")

            # 4. Download the ZIP
            # Split repo_full_name into owner and repo
            owner, repo = repo_full_name.split("/")
            artifact_id = target_artifact["id"]
            
            zip_content = await self.github.download_artifact(installation_id, owner, repo, artifact_id)

            # 5. Extract...
            await self._extract_screenshot(zip_content)

        except Exception as e:
            logger.error(f"❌ Error processing failure: {e}")

    async def _extract_screenshot(self, zip_content: bytes):
        """
        Helper to unzip in memory and find the .png
        """
        try:
            with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
                # List files
                file_list = z.namelist()
                logger.info(f"📂 Artifact contents: {file_list}")

                # Find the screenshot (Playwright usually names them test-failed-1.png or similar)
                screenshot_file = next((f for f in file_list if f.endswith(".png")), None)

                if screenshot_file:
                    logger.info(f"📸 FOUND SCREENSHOT: {screenshot_file}")
                    
                    # Save it locally just to prove we got it (Temporary)
                    os.makedirs("debug_screenshots", exist_ok=True)
                    with open(f"debug_screenshots/{os.path.basename(screenshot_file)}", "wb") as f:
                        f.write(z.read(screenshot_file))
                    logger.info("💾 Saved to debug_screenshots/ folder")
                else:
                    logger.warning("No .png found inside the artifact zip.")

        except Exception as e:
            logger.error(f"Failed to unzip artifact: {e}")