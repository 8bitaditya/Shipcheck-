"""Rectification engine (FR-6): fix generation + re-verification gate.

Pipeline for a single confirmed finding:
    1. generate_fix  -> ask the fixer model (Nemotron Super) for diff-hunk JSON,
       grounding it in the exploit evidence, and parse into a FixPatch.
    2. apply_and_verify -> apply the hunks via search/replace, fork the sandbox
       into a child branch, re-run the exact same probe (marker must be ABSENT),
       and run the repo's own test suite (must PASS).

The verdict on the fix is deterministic, exactly like the probe verdict: the
marker check and the test exit code decide it, not the LLM.
"""

from __future__ import annotations

import difflib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from shipcheck import config
from shipcheck.contracts.attack_plan import AttackPlan
from shipcheck.contracts.finding import Finding
from shipcheck.contracts.fix import DiffHunk, FixPatch, FixStatus
from shipcheck.llm.mock_llm import MockNemotronClient
from shipcheck.llm.nemotron_client import NemotronClient
from shipcheck.probes.harness import ProbeHarness
from shipcheck.sandbox.base import SandboxBase, rebase_workdir

logger = logging.getLogger(__name__)


class RectificationEngine:
    """Generates a fix for a confirmed finding and re-verifies it in a child sandbox."""

    def __init__(
        self,
        llm_client: Optional[NemotronClient] = None,
        harness: Optional[ProbeHarness] = None,
        max_regenerations: int = 2,
    ):
        if config.LLM_BACKEND == "mock" or not config.NEBIUS_API_KEY:
            self.llm = MockNemotronClient()
        else:
            self.llm = llm_client or NemotronClient()

        self.harness = harness or ProbeHarness()
        # Extra fix attempts when a patch can't be applied (search block not
        # found / ambiguous). The model gets the rejection reason as feedback.
        self.max_regenerations = max_regenerations

        prompt_path = Path(__file__).parent.parent / "llm" / "prompts" / "fixer.md"
        self.system_prompt = (
            prompt_path.read_text(encoding="utf-8")
            if prompt_path.exists()
            else "You are a security fix generator."
        )

    # ------------------------------------------------------------------ #
    # Stage 1: fix generation                                            #
    # ------------------------------------------------------------------ #
    async def generate_fix(
        self, finding: Finding, source_text: str, feedback: Optional[str] = None
    ) -> FixPatch:
        """Ask the fixer model for a diff-hunk patch grounded in the exploit evidence."""
        evidence_ctx = (
            finding.evidence.to_fixer_prompt_context()
            if finding.evidence is not None
            else "### Exploit Evidence\n(no captured evidence)"
        )
        prompt = (
            f"## Target File: {finding.target.file}\n"
            f"```\n{source_text}\n```\n\n"
            f"## Vulnerability\n"
            f"- Class: {finding.vuln_class.value}\n"
            f"- Sink: {finding.target.sink or 'unknown'}\n\n"
            f"{evidence_ctx}\n\n"
            f"Generate the fix as diff-hunk JSON."
        )
        if feedback:
            prompt += (
                f"\n\n## Previous attempt rejected\n{feedback}\n"
                f"Copy each `search` block verbatim from the target file above "
                f"(exact characters and indentation, nothing added), long enough "
                f"to match exactly once."
            )
        data = await self.llm.complete_json(
            prompt=prompt,
            system_prompt=self.system_prompt,
            tier="super",
        )
        return self._parse_fix(data, finding.finding_id)

    @staticmethod
    def _parse_fix(data: Any, finding_id: Optional[str]) -> FixPatch:
        """Normalize fixer JSON (canonical or legacy field names) into a FixPatch."""
        if not isinstance(data, dict):
            logger.warning("Fixer returned non-object JSON; producing empty patch.")
            return FixPatch(finding_id=finding_id, status=FixStatus.PROPOSED)

        raw_hunks = data.get("hunks")
        if raw_hunks is None and ("search" in data or "search_block" in data):
            # A single bare hunk object
            raw_hunks = [data]
        raw_hunks = raw_hunks or []

        hunks: List[DiffHunk] = []
        for h in raw_hunks:
            if not isinstance(h, dict):
                continue
            file = h.get("file") or h.get("file_path")
            search = h.get("search") or h.get("search_block")
            replace = h.get("replace")
            if replace is None:
                replace = h.get("replace_block", "")
            if not file or not search:
                continue
            try:
                hunks.append(
                    DiffHunk(
                        file=file,
                        search=search,
                        replace=replace,
                        allow_deletion=not bool(replace),
                    )
                )
            except Exception as exc:  # noqa: BLE001 - skip invalid hunk, keep the rest
                logger.warning("Skipping invalid fix hunk: %s", exc)

        return FixPatch(
            finding_id=finding_id,
            hunks=hunks,
            root_cause=data.get("root_cause"),
            explanation=data.get("explanation"),
            status=FixStatus.PROPOSED,
        )

    # ------------------------------------------------------------------ #
    # Stage 2: apply + re-verify (the "No PASS, No PR" gate)             #
    # ------------------------------------------------------------------ #
    async def apply_and_verify(
        self,
        finding: Finding,
        plan: AttackPlan,
        sandbox: SandboxBase,
        *,
        app_cmd: str = "python app.py",
        target_dir: Optional[str] = None,
        test_cmd: Optional[str] = "python -m pytest -q",
    ) -> FixPatch:
        """Generate, apply and re-verify a fix for one confirmed finding.

        Applies the patch in a forked child sandbox, re-runs the identical probe
        (marker must be absent) and the repo's tests (must pass). Returns the
        FixPatch with its verification fields and status set. Never raises on a
        failed fix -- it reports VERIFIED_FAILED.
        """
        # Read the primary target file to ground fix generation.
        try:
            source_text = (await sandbox.read_file(finding.target.file)).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not read %s for fix generation: %s", finding.target.file, exc)
            source_text = ""

        feedback: Optional[str] = None
        rejections: List[str] = []
        for attempt in range(1 + max(0, self.max_regenerations)):
            patch = await self.generate_fix(finding, source_text, feedback=feedback)
            patched_files = await self._apply_hunks(patch, sandbox)
            if patched_files is not None:
                break
            rejections.append(f"attempt {attempt + 1}: {patch.verification_log}")
            feedback = await self._rejection_feedback(patch, sandbox)
        else:
            # Every attempt was rejected before reaching the sandbox.
            patch.verification_log = "\n".join(rejections)
            if not patch.hunks:
                patch.status = FixStatus.VERIFIED_FAILED
            return patch

        patch.status = FixStatus.APPLIED

        # Re-verify in a child branch so the original (vulnerable) state is untouched.
        child = await sandbox.fork()
        try:
            return await self._verify_in_child(
                patch, finding, plan, sandbox, child, patched_files, rejections,
                app_cmd=app_cmd, target_dir=target_dir, test_cmd=test_cmd,
            )
        finally:
            child.cleanup()

    async def _verify_in_child(
        self, patch, finding, plan, sandbox, child, patched_files, rejections,
        *, app_cmd, target_dir, test_cmd,
    ) -> FixPatch:
        """Apply the patch in the forked child, re-attack it and run the repo tests."""
        await child.apply_files(patched_files)

        reprobe = await self.harness.execute_step(
            child, plan, app_cmd=app_cmd,
            target_dir=rebase_workdir(target_dir, sandbox, child),
        )
        marker_absent = not reprobe.marker_found
        patch.recheck_attack_marker_absent = marker_absent

        log_parts = [
            f"Re-probe verdict: {reprobe.verdict.value} (marker_found={reprobe.marker_found})",
            f"Re-probe excerpt: {reprobe.response_excerpt[:300]}",
        ]

        if test_cmd:
            test_res = await child.run(shell=test_cmd, cwd=None, timeout=120.0, disposable=True)
            tests_passed = test_res.exit_code == 0
            patch.repo_tests_passed = tests_passed
            log_parts.append(f"Repo tests exit_code={test_res.exit_code}")
            log_parts.append(f"Test output: {(test_res.stdout or '')[-500:]}")
        else:
            # No test command supplied: cannot assert regression safety.
            patch.repo_tests_passed = None
            log_parts.append("No repo test command supplied; regression gate skipped.")

        if rejections:
            log_parts = rejections + log_parts
        patch.verification_log = "\n".join(log_parts)

        # No PASS, No PR: both the marker check and the tests must pass.
        if marker_absent and patch.repo_tests_passed:
            patch.status = FixStatus.VERIFIED_PASSED
        else:
            patch.status = FixStatus.VERIFIED_FAILED

        return patch

    @staticmethod
    def _closest_block(content: str, search: str) -> Optional[str]:
        """The run of lines in `content` most similar to `search` (same line count)."""
        lines = content.splitlines()
        n = max(1, len(search.splitlines()))
        best, best_ratio = None, 0.0
        for i in range(0, max(1, len(lines) - n + 1)):
            block = "\n".join(lines[i:i + n])
            ratio = difflib.SequenceMatcher(None, block, search).ratio()
            if ratio > best_ratio:
                best, best_ratio = block, ratio
        return best if best_ratio >= 0.6 else None

    @classmethod
    async def _rejection_feedback(cls, patch: FixPatch, sandbox: SandboxBase) -> str:
        """Rejection reason plus, for a near-miss search block, the real text to copy."""
        feedback = patch.verification_log or "Patch could not be applied."
        if patch.status != FixStatus.REJECTED_SEARCH_NOT_FOUND:
            return feedback
        for hunk in patch.hunks:
            try:
                content = (await sandbox.read_file(hunk.file)).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            if hunk.search in content:
                continue
            closest = cls._closest_block(content, hunk.search)
            if closest is not None:
                feedback += (
                    f"\nYour search block for '{hunk.file}' was:\n```\n{hunk.search}\n```\n"
                    f"The closest text actually in the file is:\n```\n{closest}\n```"
                )
        return feedback

    @staticmethod
    async def _apply_hunks(patch: FixPatch, sandbox: SandboxBase) -> Optional[Dict[str, str]]:
        """Apply the hunks in memory. Returns the patched files, or None (status/log set) if rejected."""
        if not patch.hunks:
            patch.verification_log = "Fixer produced no applicable hunks."
            return None

        # Apply each hunk to its file, grouped so multiple hunks on one file chain.
        patched_files: Dict[str, str] = {}
        for hunk in patch.hunks:
            if hunk.file not in patched_files:
                try:
                    patched_files[hunk.file] = (
                        await sandbox.read_file(hunk.file)
                    ).decode("utf-8", "replace")
                except Exception as exc:  # noqa: BLE001
                    patch.status = FixStatus.REJECTED_SEARCH_NOT_FOUND
                    patch.verification_log = f"Could not read target file '{hunk.file}': {exc}"
                    return None

            new_content, ok, reason = hunk.apply_to_text(patched_files[hunk.file])
            if not ok and "not found" in reason:
                repaired = RectificationEngine._repair_trailing_artifact(hunk, patched_files[hunk.file])
                if repaired is not None:
                    new_content, ok, reason = repaired.apply_to_text(patched_files[hunk.file])
                    if ok:
                        logger.info("Repaired trailing artifact in fix hunk for %s", hunk.file)
                        hunk.search, hunk.replace = repaired.search, repaired.replace
            if not ok:
                patch.status = (
                    FixStatus.REJECTED_AMBIGUOUS_MATCH
                    if "Ambiguous" in reason
                    else FixStatus.REJECTED_SEARCH_NOT_FOUND
                )
                patch.verification_log = reason
                return None
            patched_files[hunk.file] = new_content
        return patched_files

    @staticmethod
    def _repair_trailing_artifact(hunk: DiffHunk, content: str) -> Optional[DiffHunk]:
        """Undo a known model quirk: stray `,` `>` `;` appended to the hunk's last line.

        Nemotron Super repeatedly emitted `return "...</h1>">` (or `",`) for a line
        ending in `"</h1>"`, even when shown the real text. Only that exact shape is
        repaired: every other line must match verbatim, the stray suffix must be
        1-2 of `,>;`, the real block must occur exactly once, and the same suffix
        must end the replace text (it was copied there too). The patch still has to
        pass the re-attack and the repo tests like any other.
        """
        search = hunk.search.rstrip("\n")
        lines = search.split("\n")
        last = lines[-1]
        stripped = last.rstrip(",>;")
        suffix = last[len(stripped):]
        if not suffix or len(suffix) > 2:
            return None
        real = "\n".join(lines[:-1] + [stripped])
        if content.count(real) != 1:
            return None
        replace = hunk.replace.rstrip("\n")
        if not replace.endswith(suffix):
            return None
        trailing_nl = "\n" if hunk.search.endswith("\n") and (real + "\n") in content else ""
        replace_nl = "\n" if hunk.replace.endswith("\n") else ""
        return DiffHunk(
            file=hunk.file,
            search=real + trailing_nl,
            replace=replace[: -len(suffix)] + replace_nl,
            allow_deletion=hunk.allow_deletion,
        )
