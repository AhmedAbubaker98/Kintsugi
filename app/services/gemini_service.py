"""
Gemini Service for AI-powered test fix generation.

This service uses Google's Gemini model to analyze failed tests
by examining screenshots, error logs, and test code to generate fixes.
Uses structured JSON output for reliable parsing.

Supports multimodal analysis including:
- Screenshots (PNG) - inline as image parts
- Video recordings (WebM) - uploaded via File API with polling

Uses Chat API (not stateless generate_content) to properly
handle Gemini 3's thought signatures for multi-turn conversations.
The SDK automatically preserves thought signatures when using chats.
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Optional
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
    
    thought_process: str = Field(
        description="Your internal monologue: Step-by-step technical reasoning used to diagnose the failure and arrive at the fix. Include what you observed in each evidence source (error log, screenshot, video, DOM) and how it informed your solution."
    )
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
    
    Uses Chat API to properly handle Gemini 3's thought signatures.
    The SDK automatically manages thought signature preservation across turns.
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
        
        # Store active chat sessions for multi-turn conversations
        # Key: session_id (e.g., branch name), Value: Chat object
        self._chat_sessions: dict[str, any] = {}

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

    def _log_token_usage(self, response, model_name: str, operation: str = "generation"):
        """
        Log token usage and estimated cost from Gemini response.
        
        Pricing (as of Jan 2026, per 1M tokens):
        - gemini-2.0-flash: $0.075 input / $0.30 output
        - gemini-2.0-pro: $1.25 input / $5.00 output
        - gemini-3-pro: $1.25 input / $10.00 output (estimated)
        - gemini-3-flash: $0.10 input / $0.40 output (estimated)
        
        Args:
            response: The Gemini API response containing usage_metadata.
            model_name: The model name used for pricing calculation.
            operation: Description of the operation (for logging).
        """
        try:
            usage = response.usage_metadata
            if not usage:
                logger.debug(f"💰 No usage metadata available for {operation}")
                return
            
            prompt_tokens = getattr(usage, 'prompt_token_count', 0) or 0
            output_tokens = getattr(usage, 'candidates_token_count', 0) or 0
            total_tokens = getattr(usage, 'total_token_count', 0) or (prompt_tokens + output_tokens)
            
            # Pricing per 1M tokens (estimate for latest models)
            pricing = {
                "gemini-2.0-flash": {"input": 0.075, "output": 0.30},
                "gemini-2.0-pro": {"input": 1.25, "output": 5.00},
                "gemini-3-pro": {"input": 1.25, "output": 10.00},
                "gemini-3-flash": {"input": 0.10, "output": 0.40},
                "gemini-3-pro-preview": {"input": 1.25, "output": 10.00},
            }
            
            # Find matching pricing (default to flash pricing if unknown)
            model_pricing = pricing.get("gemini-2.0-flash")  # default
            for key, prices in pricing.items():
                if key in model_name.lower():
                    model_pricing = prices
                    break
            
            # Calculate estimated cost (pricing is per 1M tokens)
            input_cost = (prompt_tokens / 1_000_000) * model_pricing["input"]
            output_cost = (output_tokens / 1_000_000) * model_pricing["output"]
            total_cost = input_cost + output_cost
            
            logger.info(
                f"💰 Token Usage [{operation}]: "
                f"input={prompt_tokens:,} | output={output_tokens:,} | total={total_tokens:,} | "
                f"est. cost=${total_cost:.4f} (in: ${input_cost:.4f}, out: ${output_cost:.4f})"
            )
            
        except Exception as e:
            logger.debug(f"Could not log token usage: {e}")

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
        session_id: str | None = None,
        is_iteration: bool = False,
    ) -> FixResponse:
        """
        Sends the broken code, error log, screenshot, video, and context to Gemini.
        
        Uses Chat API to properly handle thought signatures for multi-turn
        conversations (iterations). The SDK automatically preserves signatures.
        
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
            session_id: Unique ID for this fix session (e.g., branch name). 
                        Used to maintain chat history across iterations.
            is_iteration: If True, this is a follow-up attempt on an existing session.
        
        Returns:
            FixResponse: Structured response with fixes and explanation.
        """
        has_screenshot = screenshot_bytes is not None
        has_video = video_bytes is not None
        uploaded_video = None  # Track for cleanup
        active_model = model_name
        
        try:
            logger.info(f"🧠 Gemini ({active_model}) is thinking...")
            
            # Determine if we should use existing chat or create new one
            chat = None
            if session_id and is_iteration and session_id in self._chat_sessions:
                chat = self._chat_sessions[session_id]
                logger.info(f"🔄 Continuing existing chat session: {session_id}")

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
6. **DOM SNAPSHOT**: The HTML structure of the page at failure time (if available).
7. **REPOSITORY STRUCTURE**: List of files in the repo to understand the tech stack.

YOUR ANALYSIS PROTOCOL:
1. **Analyze the Error FIRST**: 
   - If "Timeout/Not Found": The element is missing or the selector is wrong. Check the Screenshot/Video/DOM.
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

4. **Analyze the DOM Snapshot (STRUCTURAL DEBUGGING)**:
   - If a DOM snapshot is provided, search for the actual element attributes.
   - Find exact data-testid, id, class names, and ARIA attributes that exist in the DOM.
   - Identify parent-child relationships that can help create more specific selectors.
   - Check if the expected element exists but has different attributes than the test expects.

5. **Check Context Files**:
   - If the test imports Page Objects or helpers, check if selectors are defined there.
   - The fix might need to be in an imported file, not the test itself.

6. **Generate the Fix**:
   - Apply standard best practices for stable selectors.
   - Prefer: data-testid > id > unique class > role with name > text with container context.
   - For timing issues: Add proper waitFor* methods, not arbitrary sleep/timeouts.
   - You may return fixes for MULTIPLE files if needed.

OUTPUT: Return a JSON object with:
- "thought_process": Your detailed internal monologue showing step-by-step technical reasoning. Document what you observed in each evidence source (error log, screenshot, video, DOM) and how it led to your diagnosis.
- "fixes": Array of {{"file_path": "path/to/file", "content": "full corrected content"}}
- "explanation": Brief summary of what was wrong and how you fixed it (2-3 sentences for PR description)
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
            
            # Build final instruction based on available media and iteration status
            media_parts = []
            if has_screenshot:
                media_parts.append("screenshot")
            if uploaded_video:
                media_parts.append("video recording")
            
            if is_iteration:
                # For iterations, remind the model about previous attempt
                if media_parts:
                    final_instruction = (
                        f"⚠️ ITERATION: The previous fix did NOT work. Here is the NEW error after your last attempt.\n\n"
                        f"Analyze the NEW error log, {', and '.join(media_parts)}, and generate a DIFFERENT fix. "
                        f"Your previous approach failed - try something else. Return JSON."
                    )
                else:
                    final_instruction = (
                        f"⚠️ ITERATION: The previous fix did NOT work. Here is the NEW error after your last attempt.\n\n"
                        f"Analyze the NEW error log and code, and generate a DIFFERENT fix. "
                        f"Your previous approach failed - try something else. Return JSON."
                    )
            else:
                if media_parts:
                    final_instruction = f"Analyze the error log, {', and '.join(media_parts)}, then generate robust fix(es). Return JSON."
                else:
                    final_instruction = "Analyze the error log and code, then generate robust fix(es). Return JSON. (Note: No visual media available for this run)"
            
            user_content.append(types.Part.from_text(text=final_instruction))

            # Debug: Save the complete prompt for inspection
            debug_prompt = f"{system_instruction}\n\n{'='*80}\nUSER CONTENT:\n{'='*80}\n\n"
            debug_prompt += f"[ITERATION: {is_iteration}]\n\n"
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

            # 4. Generate using Chat API (handles thought signatures automatically)
            if chat is None:
                # Create new chat session
                chat = self.client.chats.create(
                    model=active_model,
                    config=config,
                )
                if session_id:
                    self._chat_sessions[session_id] = chat
                    logger.info(f"📝 Created new chat session: {session_id}")
            
            # Send message via chat (SDK preserves thought signatures automatically)
            response = chat.send_message(user_content)

            # 5. Parse the structured response
            result = FixResponse.model_validate_json(response.text)
            
            # Log token usage and estimated cost
            self._log_token_usage(response, active_model, "fix_generation")
            
            # Debug: Save the output for inspection
            output_debug = f"MODEL: {active_model}\n\nSESSION: {session_id}\nITERATION: {is_iteration}\n\n"
            output_debug += f"RAW RESPONSE:\n{response.text}\n\n{'='*80}\nPARSED RESULT:\n{'='*80}\n\n"
            output_debug += f"Thought process:\n{result.thought_process}\n\n"
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
        
        finally:
            # Clean up uploaded video file
            if uploaded_video:
                logger.info(f"🧹 Cleaning up uploaded video: {uploaded_video.name}")
                self.delete_file(uploaded_video.name)

    def clear_session(self, session_id: str) -> bool:
        """
        Clear a chat session when the fix is complete (success or max attempts).
        Also clears any associated amendment sessions.
        
        Args:
            session_id: The session ID to clear (typically the branch name).
        
        Returns:
            bool: True if any session was cleared, False if none found.
        """
        cleared = False
        
        # Clear main fix session
        if session_id in self._chat_sessions:
            del self._chat_sessions[session_id]
            logger.info(f"🗑️ Cleared fix chat session: {session_id}")
            cleared = True
        
        # Clear amendment session if exists
        amendment_key = f"amendment:{session_id}"
        if amendment_key in self._chat_sessions:
            del self._chat_sessions[amendment_key]
            logger.info(f"🗑️ Cleared amendment chat session: {amendment_key}")
            cleared = True
        
        return cleared

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
        session_id: str | None = None,
    ) -> AmendmentResponse:
        """
        Process a user's comment/feedback and generate amendments to the fix.
        Uses Chat API to maintain conversation context if multiple amendments are requested.
        
        Args:
            comment_body: The user's comment text mentioning @kintsugi.
            comment_author: GitHub username of the commenter.
            changed_files: Dictionary of file paths to their current content (Kintsugi's changes).
            context_files: Dictionary of imported file paths to their contents.
            mentioned_files: List of file paths explicitly mentioned in the comment.
            repo_file_structure: List of all file paths in the repository.
            extra_instructions: Additional instructions from user config (optional).
            model_name: Override the default model name (optional).
            session_id: Unique identifier for this amendment conversation (branch name).
        
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
            
            # Generate using Chat API for conversation continuity
            amendment_session_key = f"amendment:{session_id}" if session_id else None
            chat = self._chat_sessions.get(amendment_session_key) if amendment_session_key else None
            
            if chat is None:
                # Create new chat session for amendments
                chat = self.client.chats.create(
                    model=active_model,
                    config=config,
                )
                if amendment_session_key:
                    self._chat_sessions[amendment_session_key] = chat
                    logger.info(f"📝 Created new amendment chat session: {amendment_session_key}")
            
            # Send message via chat
            response = chat.send_message(user_content)
            
            # Parse the structured response
            result = AmendmentResponse.model_validate_json(response.text)
            
            # Log token usage and estimated cost
            self._log_token_usage(response, active_model, "amendment")
            
            # Debug: Save the output
            output_debug = f"MODEL: {active_model}\n\nSESSION: {amendment_session_key}\n\nRAW RESPONSE:\n{response.text}\n\n{'='*80}\nPARSED RESULT:\n{'='*80}\n\n"
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
