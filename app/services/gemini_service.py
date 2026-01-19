"""
Gemini Service for AI-powered test fix generation.

This service uses Google's Gemini model to analyze failed tests
by examining screenshots, error logs, and test code to generate fixes.
Uses structured JSON output for reliable parsing.
"""

import logging
import os
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


class GeminiService:
    """
    Service for generating test fixes using Google Gemini.
    
    Uses multimodal capabilities to analyze screenshots alongside
    code and error logs to understand UI state changes.
    """
    
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

    def generate_fix(
        self,
        primary_file_path: str,
        primary_file_content: str,
        error_log: str,
        screenshot_bytes: bytes | None = None,
        context_files: dict[str, str] | None = None,
        repo_file_structure: list[str] | None = None,
        extra_instructions: str | None = None,
        model_name: str | None = None,
    ) -> FixResponse:
        """
        Sends the broken code, error log, screenshot, and context to Gemini.
        
        Args:
            primary_file_path: Path of the broken test file.
            primary_file_content: Content of the broken test file.
            error_log: The CI/CD error log showing what failed.
            screenshot_bytes: PNG screenshot of the UI at failure time (optional).
            context_files: Dictionary of imported file paths to their contents.
            repo_file_structure: List of all file paths in the repository.
            extra_instructions: Additional instructions from user config (optional).
            model_name: Override the default model name (optional).
        
        Returns:
            FixResponse: Structured response with fixes and explanation.
        """
        has_screenshot = screenshot_bytes is not None
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
5. **REPOSITORY STRUCTURE**: List of files in the repo to understand the tech stack.

YOUR ANALYSIS PROTOCOL:
1. **Analyze the Error FIRST**: 
   - If "Timeout/Not Found": The element is missing or the selector is wrong. Check the Screenshot.
   - If "Strict Mode Violation" or "Ambiguous": The selector matches multiple elements. Make it more specific.
   - If "Visual/Layout Error": The UI shifted. Adjust assertions.

2. **Analyze the Screenshot**: 
   - Compare the visual reality to the code's expectation.
   - Identify unique attributes (data-testid, id, unique class, role with name).
   - NEVER use a selector that could match multiple elements.

3. **Check Context Files**:
   - If the test imports Page Objects or helpers, check if selectors are defined there.
   - The fix might need to be in an imported file, not the test itself.

4. **Generate the Fix**:
   - Apply standard best practices for stable selectors.
   - Prefer: data-testid > id > unique class > role with name > text with container context.
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
            
            # Add screenshot if available
            if has_screenshot:
                user_content.append(types.Part.from_bytes(data=screenshot_bytes, mime_type="image/png"))
                final_instruction = "Analyze the error log and screenshot, then generate robust fix(es). Return JSON."
            else:
                final_instruction = "Analyze the error log and code, then generate robust fix(es). Return JSON. (Note: No screenshot available for this run)"
            
            user_content.append(types.Part.from_text(text=final_instruction))

            # Debug: Save the complete prompt for inspection
            debug_prompt = f"{system_instruction}\n\n{'='*80}\nUSER CONTENT:\n{'='*80}\n\n"
            debug_prompt += f"{code_section}{context_section}{structure_section}\n\n--- ERROR LOG ---\n{error_log}\n\n"
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
