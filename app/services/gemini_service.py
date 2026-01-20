"""
Gemini Service for AI-powered test fix generation.

This service uses Google's Gemini model to analyze failed tests
by examining screenshots, error logs, and test code to generate fixes.
Uses structured JSON output for reliable parsing.

Supports multimodal analysis including:
- Screenshots (PNG) - inline as image parts
- Video recordings (WebM) - uploaded via File API with polling
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from app.core.config import settings

logger = logging.getLogger(__name__)


class FileFix(BaseModel):
    """A single file fix."""
    file_path: str = Field(description="The path of the file to update")
    content: str = Field(description="The complete corrected file content")


class FixResponse(BaseModel):
    """Structured response from Gemini containing fixes and explanation."""
    
    fixes: list[FileFix] = Field(
        description="List of file fixes to apply. Usually just the broken test file, but may include imported files if they need changes."
    )
    explanation: str = Field(
        description="A concise summary of what was wrong and how it was fixed (2-3 sentences)"
    )


class AmendmentResponse(BaseModel):
    """Structured response from Gemini for comment-based amendments."""
    
    fixes: list[FileFix] = Field(
        description="List of file fixes to apply based on the user's feedback."
    )
    reply: str = Field(
        description="A friendly reply to the user explaining what changes were made (will be posted as a PR comment)."
    )


class GeminiService:
    """
    Service for generating test fixes using Google Gemini.
    
    Uses multimodal capabilities to analyze screenshots alongside
    code and error logs to understand UI state changes.
    
    Supports video analysis via File API for temporal debugging
    (timing issues, animations, spinners, button flickers).
    """
    
    # Video upload polling settings
    VIDEO_POLL_INTERVAL = 2  # seconds between state checks
    VIDEO_POLL_TIMEOUT = 120  # max seconds to wait for ACTIVE state
    
    def __init__(self):
        """Initialize the Gemini client with API key from settings."""
        self.client = genai.Client(api_key=settings.gemini_api_key.get_secret_value())
        self.debug_dir = "debug_prompts"
        self.output_dir = "debug_outputs"
        os.makedirs(self.debug_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

    def _rotate_debug_file(self, directory: str, prefix: str, content: str):
        """
        Save content to debug files with rotation, keeping only the last 3.
        Rotates: {prefix}_1.txt (newest) -> {prefix}_2.txt -> {prefix}_3.txt (oldest)
        """
        try:
            # Rotate existing files
            if os.path.exists(f"{directory}/{prefix}_2.txt"):
                os.replace(
                    f"{directory}/{prefix}_2.txt",
                    f"{directory}/{prefix}_3.txt"
                )
            if os.path.exists(f"{directory}/{prefix}_1.txt"):
                os.replace(
                    f"{directory}/{prefix}_1.txt",
                    f"{directory}/{prefix}_2.txt"
                )
            
            # Save new file as _1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(f"{directory}/{prefix}_1.txt", "w", encoding="utf-8") as f:
                f.write(f"=== {prefix.upper()} AT {timestamp} ===\n\n")
                f.write(content)
            
            logger.debug(f"💾 Saved to {directory}/{prefix}_1.txt")
        except Exception as e:
            logger.warning(f"Failed to save debug file: {e}")

    def _save_prompt_debug(self, prompt_content: str):
        """
        Save the prompt to debug files, keeping only the last 3 prompts.
        Rotates: prompt_1.txt (newest) -> prompt_2.txt -> prompt_3.txt (oldest)
        """
        self._rotate_debug_file(self.debug_dir, "sent_prompt", prompt_content)

    def _save_output_debug(self, output_content: str):
        """
        Save the output to debug files, keeping only the last 3 outputs.
        Rotates: output_1.txt (newest) -> output_2.txt -> output_3.txt (oldest)
        """
        self._rotate_debug_file(self.output_dir, "gemini_output", output_content)

    def upload_video(self, video_bytes: bytes, filename: str = "recording.webm") -> types.File | None:
        """
        Upload a video file to Gemini's File API and wait for it to become ACTIVE.
        
        Videos must be uploaded via the File API (not inline) due to processing requirements.
        The file goes through PROCESSING state before becoming ACTIVE.
        
        Args:
            video_bytes: The raw video file content (WebM format).
            filename: Name for the uploaded file (used for identification).
        
        Returns:
            types.File: The uploaded file object ready for use in prompts, or None if failed.
        """
        try:
            logger.info(f"📹 Uploading video ({len(video_bytes):,} bytes) to Gemini File API...")
            
            # Upload the file
            uploaded_file = self.client.files.upload(
                file=video_bytes,
                config=types.UploadFileConfig(
                    display_name=filename,
                    mime_type="video/webm"
                )
            )
            
            logger.info(f"📤 Upload initiated: {uploaded_file.name} (state: {uploaded_file.state})")
            
            # Poll until file is ACTIVE (or timeout)
            start_time = time.time()
            while uploaded_file.state == "PROCESSING":
                elapsed = time.time() - start_time
                if elapsed > self.VIDEO_POLL_TIMEOUT:
                    logger.error(f"⏰ Video processing timed out after {self.VIDEO_POLL_TIMEOUT}s")
                    self.delete_file(uploaded_file.name)
                    return None
                
                logger.debug(f"⏳ Video still processing... ({elapsed:.1f}s elapsed)")
                time.sleep(self.VIDEO_POLL_INTERVAL)
                
                # Refresh file state
                uploaded_file = self.client.files.get(name=uploaded_file.name)
            
            if uploaded_file.state == "ACTIVE":
                elapsed = time.time() - start_time
                logger.info(f"✅ Video ready! Processing took {elapsed:.1f}s")
                return uploaded_file
            else:
                logger.error(f"❌ Video upload failed with state: {uploaded_file.state}")
                self.delete_file(uploaded_file.name)
                return None
                
        except Exception as e:
            logger.error(f"❌ Video upload failed: {e}")
            return None

    def delete_file(self, file_name: str) -> bool:
        """
        Delete a file from Gemini's File API.
        
        Should be called after analysis to clean up uploaded videos.
        
        Args:
            file_name: The name/ID of the file to delete (e.g., "files/abc123").
        
        Returns:
            bool: True if deletion succeeded, False otherwise.
        """
        try:
            self.client.files.delete(name=file_name)
            logger.info(f"🗑️ Deleted uploaded file: {file_name}")
            return True
        except Exception as e:
            logger.warning(f"⚠️ Failed to delete file {file_name}: {e}")
            return False

    def generate_fix(
        self,
        primary_file_path: str,
        primary_file_content: str,
        error_log: str,
        screenshot_bytes: bytes | None = None,
        video_bytes: bytes | None = None,
        context_files: dict[str, str] | None = None,
        repo_file_structure: list[str] | None = None,
        extra_instructions: str | None = None,
        model_name: str | None = None,
    ) -> FixResponse:
        """
        Sends the broken code, error log, screenshot, video, and context to Gemini.
        
        Args:
            primary_file_path: Path of the broken test file.
            primary_file_content: Content of the broken test file.
            error_log: The CI/CD error log showing what failed.
            screenshot_bytes: PNG screenshot of the UI at failure time (optional).
            video_bytes: WebM video recording of the test failure (optional).
            context_files: Dictionary of imported file paths to their contents.
            repo_file_structure: List of all file paths in the repository.
            extra_instructions: Additional instructions from user config (optional).
            model_name: Override the default model name (optional).
        
        Returns:
            FixResponse: Structured response with fixes and explanation.
        """
        has_screenshot = screenshot_bytes is not None
        has_video = video_bytes is not None
        uploaded_video = None  # Track for cleanup
        # Use provided model or fallback to default
        active_model = model_name
        
        try:
            logger.info(f"🧠 Gemini ({active_model}) is thinking...")

            # Build context sections
            context_files = context_files or {}
            repo_file_structure = repo_file_structure or []
            
            # Format context files
            context_section = ""
            if context_files:
                context_section = "\n\n--- IMPORTED DEPENDENCIES (Context Files) ---\n"
                for path, content in context_files.items():
                    context_section += f"\n### {path}\n```\n{content}\n```\n"
            
            # Format file structure (truncate if too long)
            structure_section = ""
            if repo_file_structure:
                truncated = repo_file_structure[:100]  # Limit to 100 files
                structure_section = f"\n\n--- REPOSITORY FILE STRUCTURE ---\n{chr(10).join(truncated)}"
                if len(repo_file_structure) > 100:
                    structure_section += f"\n... and {len(repo_file_structure) - 100} more files"

            # 1. Prepare the System Instruction (Error-First Analysis)
            system_instruction = f"""
You are Kintsugi, an expert Senior Software Development Engineer in Test.
Your goal is to fix broken E2E tests (Playwright, Cypress, Selenium, etc.) by synthesizing Code, Logs, and Visuals.

ANALYZING: {primary_file_path}

INPUTS:
1. **BROKEN TEST FILE**: The primary test file that failed.
2. **IMPORTED DEPENDENCIES**: Files imported by the test (Page Objects, helpers, components).
3. **ERROR LOG**: The runtime exception from CI/CD.
4. **SCREENSHOT**: The visual state of the UI at the moment of failure.
5. **VIDEO RECORDING**: A video recording of the test execution (if available).
6. **REPOSITORY STRUCTURE**: List of files in the repo to understand the tech stack.

YOUR ANALYSIS PROTOCOL:
1. **Analyze the Error FIRST**: 
   - If "Timeout/Not Found": The element is missing or the selector is wrong. Check the Screenshot/Video.
   - If "Strict Mode Violation" or "Ambiguous": The selector matches multiple elements. Make it more specific.
   - If "Visual/Layout Error": The UI shifted. Adjust assertions.

2. **Analyze the Screenshot**: 
   - Compare the visual reality to the code's expectation.
   - Identify unique attributes (data-testid, id, unique class, role with name).
   - NEVER use a selector that could match multiple elements.

3. **Analyze the Video (TEMPORAL DEBUGGING)**:
   - If a video is provided, use it to understand timing and animation issues.
   - Look for: spinners, loading states, animations, button flickers, elements appearing/disappearing.
   - Check if the test failed due to a race condition (element appeared but test checked too early/late).
   - Correlate error log timestamps with video frames to pinpoint the exact moment of failure.
   - If the failure is timing-related, suggest adding waitFor conditions or increasing timeouts.

4. **Check Context Files**:
   - If the test imports Page Objects or helpers, check if selectors are defined there.
   - The fix might need to be in an imported file, not the test itself.

5. **Generate the Fix**:
   - Apply standard best practices for stable selectors.
   - Prefer: data-testid > id > unique class > role with name > text with container context.
   - For timing issues: Add proper waitFor* methods, not arbitrary sleep/timeouts.
   - You may return fixes for MULTIPLE files if needed.

OUTPUT: Return a JSON object with:
- "fixes": Array of {{"file_path": "path/to/file", "content": "full corrected content"}}
- "explanation": Brief summary of what was wrong and how you fixed it
"""
            # Add extra instructions from user config if provided
            if extra_instructions:
                system_instruction += f"\n\nADDITIONAL USER INSTRUCTIONS:\n{extra_instructions}"

            # 2. Construct the Payload (Multimodal or Text-only)
            code_section = f"--- BROKEN TEST FILE: {primary_file_path} ---\n{primary_file_content}"
            
            # Build user content parts conditionally
            user_content = [
                types.Part.from_text(
                    text=f"{code_section}{context_section}{structure_section}\n\n--- ERROR LOG ---\n{error_log}"
                )
            ]
            
            # Add video if available (must be uploaded to File API)
            if has_video:
                logger.info("🎬 Processing video for temporal debugging...")
                uploaded_video = self.upload_video(video_bytes, f"failure_{primary_file_path.replace('/', '_')}.webm")
                if uploaded_video:
                    user_content.append(types.Part.from_uri(file_uri=uploaded_video.uri, mime_type="video/webm"))
                    logger.info("🎬 Video attached to analysis")
                else:
                    logger.warning("⚠️ Video upload failed, proceeding without video")
            
            # Add screenshot if available
            if has_screenshot:
                user_content.append(types.Part.from_bytes(data=screenshot_bytes, mime_type="image/png"))
            
            # Build final instruction based on available media
            media_parts = []
            if has_screenshot:
                media_parts.append("screenshot")
            if uploaded_video:
                media_parts.append("video recording")
            
            if media_parts:
                final_instruction = f"Analyze the error log, {', and '.join(media_parts)}, then generate robust fix(es). Return JSON."
            else:
                final_instruction = "Analyze the error log and code, then generate robust fix(es). Return JSON. (Note: No visual media available for this run)"
            
            user_content.append(types.Part.from_text(text=final_instruction))

            # Debug: Save the complete prompt for inspection
            debug_prompt = f"{system_instruction}\n\n{'='*80}\nUSER CONTENT:\n{'='*80}\n\n"
            debug_prompt += f"{code_section}{context_section}{structure_section}\n\n--- ERROR LOG ---\n{error_log}\n\n"
            if uploaded_video:
                debug_prompt += f"[VIDEO ATTACHED: video/webm - {uploaded_video.name}]\n\n"
            else:
                debug_prompt += "[NO VIDEO AVAILABLE]\n\n"
            debug_prompt += "[SCREENSHOT ATTACHED: image/png]\n\n" if has_screenshot else "[NO SCREENSHOT AVAILABLE]\n\n"
            debug_prompt += final_instruction
            self._save_prompt_debug(debug_prompt)

            # 3. Configure for Structured JSON Output
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.1,  # Low temperature for code precision
                response_mime_type="application/json",
                response_schema=FixResponse,
            )

            # 4. Generate
            response = self.client.models.generate_content(
                model=active_model,
                contents=[
                    types.Content(
                        role="user",
                        parts=user_content
                    )
                ],
                config=config
            )

            # 5. Parse the structured response
            result = FixResponse.model_validate_json(response.text)
            
            # Debug: Save the output for inspection
            output_debug = f"MODEL: {active_model}\n\nRAW RESPONSE:\n{response.text}\n\n{'='*80}\nPARSED RESULT:\n{'='*80}\n\n"
            output_debug += f"Explanation: {result.explanation}\n\n"
            output_debug += f"Fixes ({len(result.fixes)} file(s)):\n"
            for fix in result.fixes:
                output_debug += f"\n--- {fix.file_path} ---\n{fix.content}\n"
            self._save_output_debug(output_debug)
            
            logger.info(f"✅ Gemini generated {len(result.fixes)} fix(es) successfully")
            logger.debug(f"Explanation: {result.explanation}")
            
            return result

        except Exception as e:
            logger.error(f"❌ Gemini Generation Failed: {e}")
            raise

    def generate_amendment(
        self,
        comment_body: str,
        comment_author: str,
        changed_files: dict[str, str],
        context_files: dict[str, str] | None = None,
        mentioned_files: list[str] | None = None,
        repo_file_structure: list[str] | None = None,
        extra_instructions: str | None = None,
        model_name: str | None = None,
    ) -> AmendmentResponse:
        """
        Process a user's comment/feedback and generate amendments to the fix.
        
        Args:
            comment_body: The user's comment text mentioning @kintsugi.
            comment_author: GitHub username of the commenter.
            changed_files: Dictionary of file paths to their current content (Kintsugi's changes).
            context_files: Dictionary of imported file paths to their contents.
            mentioned_files: List of file paths explicitly mentioned in the comment.
            repo_file_structure: List of all file paths in the repository.
            extra_instructions: Additional instructions from user config (optional).
            model_name: Override the default model name (optional).
        
        Returns:
            AmendmentResponse: Structured response with fixes and a reply message.
        """
        active_model = model_name
        
        try:
            logger.info(f"🧠 Gemini ({active_model}) processing amendment request from @{comment_author}...")
            
            # Build context sections
            context_files = context_files or {}
            mentioned_files = mentioned_files or []
            repo_file_structure = repo_file_structure or []
            
            # Format changed files (Kintsugi's previous changes)
            changed_section = "--- FILES KINTSUGI PREVIOUSLY CHANGED ---\n"
            for path, content in changed_files.items():
                changed_section += f"\n### {path}\n```\n{content}\n```\n"
            
            # Format context files (dependencies)
            context_section = ""
            if context_files:
                context_section = "\n\n--- IMPORTED DEPENDENCIES (Context Files) ---\n"
                for path, content in context_files.items():
                    context_section += f"\n### {path}\n```\n{content}\n```\n"
            
            # Format mentioned files
            mentioned_section = ""
            if mentioned_files:
                mentioned_section = f"\n\n--- FILES MENTIONED IN COMMENT ---\n{chr(10).join(mentioned_files)}"
            
            # Format file structure (truncate if too long)
            structure_section = ""
            if repo_file_structure:
                truncated = repo_file_structure[:100]
                structure_section = f"\n\n--- REPOSITORY FILE STRUCTURE ---\n{chr(10).join(truncated)}"
                if len(repo_file_structure) > 100:
                    structure_section += f"\n... and {len(repo_file_structure) - 100} more files"
            
            # System instruction for amendment processing
            system_instruction = f"""
You are Kintsugi, an expert Senior Software Development Engineer in Test.
A user has commented on your Pull Request with feedback or a request for changes.

YOUR TASK:
1. Read and understand the user's feedback carefully.
2. Look at the files you previously changed (provided below).
3. If the user mentions specific files, pay extra attention to those.
4. Generate the amended file content based on their request.
5. Write a friendly, professional reply acknowledging their feedback.

GUIDELINES:
- If the user asks to change selectors, locators, or assertions, do so.
- If the user points out an error in your fix, correct it.
- If the user wants a different approach, implement it.
- If files are mentioned in the comment (like "check src/pages/login.ts"), look for them in the context.
- Your reply should be concise and explain what you changed.
- Use a friendly tone (you're a helpful bot, not a formal assistant).

USER: @{comment_author}

OUTPUT: Return a JSON object with:
- "fixes": Array of {{"file_path": "path/to/file", "content": "full corrected content"}}
- "reply": A friendly message to post as a PR comment (1-3 sentences)
"""
            if extra_instructions:
                system_instruction += f"\n\nADDITIONAL USER INSTRUCTIONS:\n{extra_instructions}"
            
            # Construct user content
            user_content = [
                types.Part.from_text(
                    text=f"--- USER COMMENT ---\n{comment_body}\n\n{changed_section}{context_section}{mentioned_section}{structure_section}"
                ),
                types.Part.from_text(
                    text="Process this feedback and generate the requested amendments. Return JSON."
                )
            ]
            
            # Debug: Save the prompt
            debug_prompt = f"{system_instruction}\n\n{'='*80}\nUSER CONTENT:\n{'='*80}\n\n"
            debug_prompt += f"--- USER COMMENT ---\n{comment_body}\n\n{changed_section}{context_section}{mentioned_section}{structure_section}"
            self._save_prompt_debug(debug_prompt)
            
            # Configure for structured JSON output
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2,  # Slightly higher for more natural replies
                response_mime_type="application/json",
                response_schema=AmendmentResponse,
            )
            
            # Generate
            response = self.client.models.generate_content(
                model=active_model,
                contents=[
                    types.Content(
                        role="user",
                        parts=user_content
                    )
                ],
                config=config
            )
            
            # Parse the structured response
            result = AmendmentResponse.model_validate_json(response.text)
            
            # Debug: Save the output
            output_debug = f"MODEL: {active_model}\n\nRAW RESPONSE:\n{response.text}\n\n{'='*80}\nPARSED RESULT:\n{'='*80}\n\n"
            output_debug += f"Reply: {result.reply}\n\n"
            output_debug += f"Fixes ({len(result.fixes)} file(s)):\n"
            for fix in result.fixes:
                output_debug += f"\n--- {fix.file_path} ---\n{fix.content}\n"
            self._save_output_debug(output_debug)
            
            logger.info(f"✅ Gemini generated {len(result.fixes)} amendment(s) successfully")
            
            return result
        
        except Exception as e:
            logger.error(f"❌ Gemini Amendment Generation Failed: {e}")
            raise
        
        finally:
            # Clean up uploaded video file
            if uploaded_video:
                logger.info(f"🧹 Cleaning up uploaded video: {uploaded_video.name}")
                self.delete_file(uploaded_video.name)
