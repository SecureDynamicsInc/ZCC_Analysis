"""
ZDX Remediation Errors — authoritative reference data.

Normalized from the Zscaler documentation "Digital Experience Monitoring
(ZDX): Remediation Errors".

41 error rows for ZDX Remediation jobs (admin-triggered scripts +
log-collection that run on managed endpoints). Every code uses the
prefix ``ZUPM_WORKFLOW_E_CODE_*``. 41 rows = 40 distinct codes + 1
duplicate row (SCRIPT_CERT_VALIDATION_FAILED).

FAMILIES (our derivation by code-name substring):

  workflow      — overall remediation job lifecycle (12 rows)
  task          — task-level validation / retry / abort (3 rows)
  script        — script signing / certs / execution states (18 rows)
                  Note: SCRIPT_CERT_VALIDATION_FAILED is shared by
                  TWO distinct error messages — both rows preserved.
                  17 distinct codes + 1 duplicate = 18 rows.
  log_fetch     — log-collection sub-flow (3 rows)
  notification  — user-notification framework (5 rows)

SEVERITY DERIVATION:

  critical — security failures (unsigned / revoked / signature invalid
             / cert validation failed) and infrastructure breaks
             (handler init / orchestrator RPC / notification init)
  warning  — runtime errors needing investigation (download failed,
             execution err, timeout) and config issues (unsupported
             task category, policy config missing)
  info     — benign user actions and "No action required" rows
             (user deferred / declined, max defer reached, policy
             aborted, etc.)

WHERE THESE APPEAR:

ZDX Remediation errors surface in the Remediation job results panel
in the ZDX admin console. They can also appear in ZCC tray logs and
UPM (Universal Policy Manager) component logs when a remediation job
fails on the endpoint — search for "ZUPM_WORKFLOW_E_CODE_" in tray
logs to find them. This module provides the canonical decoding when
that string shows up.

Source URL: https://help.zscaler.com/zdx/remediation-errors
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict  # type: ignore


class ZdxRemediationError(TypedDict, total=False):
    """One row from the ZDX Remediation Errors documentation.

    Fields:
      code               — the ZUPM_WORKFLOW_E_CODE_* string (documented).
                           Note: SCRIPT_CERT_VALIDATION_FAILED is
                           shared by two rows with different error
                           messages — use ERRORS_BY_CODE_ALL for full.
      error_message      — documented from the documentation
      error_description  — documented from the documentation
      recommended_action — documented from the documentation
      family             — workflow | task | script | log_fetch | notification
      severity_hint      — critical | warning | info
    """
    code: str
    error_message: str
    error_description: str
    recommended_action: str
    family: str
    severity_hint: str


# =====================================================================
# Workflow family (12 rows) — overall job lifecycle
# =====================================================================

_WORKFLOW: List[ZdxRemediationError] = [
    {
        "code": "ZUPM_WORKFLOW_E_CODE_INTERNAL_ERR",
        "error_message": "Zscaler Internal Error",
        "error_description": "There was an unexpected internal error.",
        "recommended_action": "No action required.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_EXECUTION_TIMEOUT",
        "error_message": "Workflow failed due to timeout during execution",
        "error_description": "The Remediation job reached its expiration and cannot run anymore.",
        "recommended_action": "Extend the Remediation job's expiration.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_EXPIRED_BEFORE_START",
        "error_message": "Workflow expired before it could start.",
        "error_description": "The Remediation job expired before it could start the run.",
        "recommended_action": "Extend the Remediation job's expiration.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_EXPIRED_DURING_EXEC",
        "error_message": "Workflow expired during execution.",
        "error_description": "The script expired during its run.",
        "recommended_action": "Extend the Remediation job's duration.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_POLICY_ABORTED",
        "error_message": "Workflow is aborted due to policy rules.",
        "error_description": "The Remediation job was aborted by an admin.",
        "recommended_action": "No action required.",
        "family": "workflow",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_REM_DISABLED",
        "error_message": "Workflow is aborted due to Remote Execution is disabled for the user/device.",
        "error_description": "The Remediation job aborted because the Remediation Settings were not enabled for the user or device.",
        "recommended_action": "Enable Remediation Settings for the user or device. To learn more, see Configuring Remediation Settings.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_ABORTED_ON_TASK_ERR",
        "error_message": "Workflow is aborted due to task error.",
        "error_description": "The Remediation job aborted because there is a task that the user's device does not recognize or support.",
        "recommended_action": "Edit the script to ensure all tasks are applicable to the user's device.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_UNSUPPORTED_TASK_CATEGORY",
        "error_message": "Workflow failed due to unsupported task category received.",
        "error_description": "The Remediation job aborted because there is a task with a category that the user's device does not recognize or support.",
        "recommended_action": "Edit the script to ensure all tasks with a category are applicable to the user's device. The currently supported categories are SCRIPT and LOG_COLLECTION.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_POLICY_CONFIG_MISSING",
        "error_message": "Workflow failed due to policy config for this workflow is not received.",
        "error_description": "The Remediation job aborted because the script is invalid due to removal or expired certification.",
        "recommended_action": "Upload the Remediation job with a valid certification.",
        "family": "workflow",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_USER_DEFERRED",
        "error_message": "Workflow rescheduled due to user deferral.",
        "error_description": "The Remediation job was rescheduled.",
        "recommended_action": "No action required.",
        "family": "workflow",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_MAX_DEFER_REACHED",
        "error_message": "Workflow failed due to hitting maximum defer count limit.",
        "error_description": "The Remediation job exceeded the maximum number of Remediation jobs.",
        "recommended_action": "No action required.",
        "family": "workflow",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOT_FOUND_ON_DEVICE",
        "error_message": "Workflow is skipped as it's not found on device.",
        "error_description": "The Remediation job failed because an admin aborted it.",
        "recommended_action": "No action required.",
        "family": "workflow",
        "severity_hint": "info",
    },
]


# =====================================================================
# Task family (3 rows) — task-level validation / retry / abort
# =====================================================================

_TASK: List[ZdxRemediationError] = [
    {
        "code": "ZUPM_WORKFLOW_E_CODE_TASK_VALIDATION_ERR",
        "error_message": "Task validation failure.",
        "error_description": "The script contains an invalid task object, a null task, or the category is not supported.",
        "recommended_action": "Revise your script to contain valid task objects, ensure the task is not set to null, and ensure the category is supported.",
        "family": "task",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_TASK_MAX_RETRY_REACHED",
        "error_message": "Task failed due to hitting maximum retry count limit.",
        "error_description": "The Remediation job failed and reached the maximum number of retries.",
        "recommended_action": "Rerun the script when the user's device is available.",
        "family": "task",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_TASK_ABORTED",
        "error_message": "Task is aborted due to policy rules.",
        "error_description": "The Remediation job was aborted because an admin aborted it or there was an overriding script run.",
        "recommended_action": "No action required.",
        "family": "task",
        "severity_hint": "info",
    },
]


# =====================================================================
# Script family (17 rows) — signing / certs / execution states
# Note: SCRIPT_CERT_VALIDATION_FAILED is shared by TWO rows
# (the documentation lists both "Script certificate verification failure" and
# "Script signature validation failure" pointing at the same code).
# =====================================================================

_SCRIPT: List[ZdxRemediationError] = [
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_DOWNLOAD_FAILED",
        "error_message": "Failed to download script.",
        "error_description": "The script cannot be downloaded due to the network connection or invalid URL.",
        "recommended_action": "Retry downloading when the network connection is stable.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_CERT_VALIDATION_FAILED",
        "error_message": "Script certificate verification failure.",
        "error_description": "The script's certification is unverified or missing.",
        "recommended_action": "Check the client's device to see if there are missing certificates.",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_CERT_VALIDATION_FAILED",
        "error_message": "Script signature validation failure.",
        "error_description": "The script's certificate cannot be verified.",
        "recommended_action": "Contact Zscaler Support.",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_INVALID_SIGNATURE",
        "error_message": "Script signature is invalid.",
        "error_description": "The script's digital signature is invalid.",
        "recommended_action": "Check the script's properties to validate the digital signature.",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_UNSIGNED",
        "error_message": "Script is unsigned.",
        "error_description": "The script is not signed, or the signature is invalid.",
        "recommended_action": "Check the script's signature for validity as it is invalid in the Properties of Windows File Explorer.",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_CERT_REVOKED",
        "error_message": "Script certificate is revoked.",
        "error_description": "The script certificate is revoked.",
        "recommended_action": "Check if the revocation server is accessible and the OS is up-to-date. If these actions do not work, then disable the revocation check. To learn more, see Configuring Remediation Settings.",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_EXECUTION_POL_DISALLOWED",
        "error_message": "Script execution blocked by execution policy: disallowed.",
        "error_description": "The Remediation job is blocked due to Powershell Execution Policy's Restricted Mode.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_EXECUTION_POL_SIGNED_ONLY",
        "error_message": "Script execution blocked by execution policy: only signed scripts are allowed.",
        "error_description": "The Remediation job is blocked due to PowerShell Execution Policy's Restricted Mode.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_TYPE_NOT_SUPPORTED",
        "error_message": "Unsupported script type.",
        "error_description": "The Remediation job has an unsupported type.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_UNKNOWN_RESULT",
        "error_message": "Script execution failed due to unknown result.",
        "error_description": "The script failed to run due to an unknown JSON response.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_EXECUTION_ERR",
        "error_message": "Script execution error or exception occurred.",
        "error_description": "The script failed to run due to runtime errors within the script.",
        "recommended_action": "Check and resolve the runtime errors in the script.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_EXECUTION_TIMEDOUT",
        "error_message": "Script execution failed due to timeout.",
        "error_description": "The script failed to run due to the defined timeout.",
        "recommended_action": "Extend the runtime of the Remediation job. To learn more, see Viewing and Managing Remediation jobs.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_EXECUTION_ABORTED",
        "error_message": "Script execution aborted.",
        "error_description": "The Remediation job was aborted by an admin.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_RUN_USER_DEFERRED",
        "error_message": "Script execution is deferred by user action.",
        "error_description": "The user postponed the Remediation job.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_RUN_USER_DECLINED",
        "error_message": "Script execution is declined by user action.",
        "error_description": "The user declined the Remediation job.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_HANDLER_INIT_FAILED",
        "error_message": "Script execution failed due to handler init failure.",
        "error_description": "The Remediation job failed to initialize.",
        "recommended_action": "Contact Zscaler Support",
        "family": "script",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_JOB_ID_NOT_FOUND",
        "error_message": "Script job ID not found in ZCC SE Platform.",
        "error_description": "The Remediation job has an invalid ID in the Zscaler Client Connector Script Execution (SE) Platform.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_SCRIPT_ORCHESTRATOR_RPC_FAILURE",
        "error_message": "Script execution failed due to Script Orchestrator Service is not started or unavailable.",
        "error_description": "The Remediation job cannot run because of the unavailable Script Orchestrator Service.",
        "recommended_action": "No action required.",
        "family": "script",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Log Fetch family (3 rows)
# =====================================================================

_LOG_FETCH: List[ZdxRemediationError] = [
    {
        "code": "ZUPM_WORKFLOW_E_CODE_LOG_FETCH_MAX_DEFER_REACHED",
        "error_message": "Script execution failed due to hitting maximum defer count limit.",
        "error_description": "The Remediation job did not run because you have exceeded the maximum number of Remediation jobs.",
        "recommended_action": "Wait to complete the other Remediation jobs and then re-run the job. To learn more, see Ranges & Limitations.",
        "family": "log_fetch",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_LOG_FETCH_ERR",
        "error_message": "Log collection error or exception occurred.",
        "error_description": "Unable to collect data logs due to an internal error.",
        "recommended_action": "No action required.",
        "family": "log_fetch",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_LOG_FETCH_TIMEDOUT",
        "error_message": "Log collection failed due to timeout.",
        "error_description": "Unable to collect data logs because the upload process exceeds runtime.",
        "recommended_action": "No action required.",
        "family": "log_fetch",
        "severity_hint": "warning",
    },
]


# =====================================================================
# Notification family (5 rows)
# =====================================================================

_NOTIFICATION: List[ZdxRemediationError] = [
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOTIFICATION_INTERNAL_ERR",
        "error_message": "Internal error when handling notification.",
        "error_description": "An internal error occurred during notification.",
        "recommended_action": "Contact Zscaler Support.",
        "family": "notification",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOTIFICATION_SEND_FAILURE",
        "error_message": "Failed to send user notification.",
        "error_description": "Unable to send user notification.",
        "recommended_action": "Contact Zscaler Support.",
        "family": "notification",
        "severity_hint": "warning",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOTIFICATION_NO_RESPONSE",
        "error_message": "No response from the user.",
        "error_description": "Unable to receive the user's response due to timeout.",
        "recommended_action": "No action required.",
        "family": "notification",
        "severity_hint": "info",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOTIFICATION_HANDLER_INIT_FAILED",
        "error_message": "Notification handler init failure.",
        "error_description": "Unable to send notification due to error initializing.",
        "recommended_action": "Contact Zscaler Support.",
        "family": "notification",
        "severity_hint": "critical",
    },
    {
        "code": "ZUPM_WORKFLOW_E_CODE_NOTIFICATION_FRAMEWORK_DISABLED",
        "error_message": "Zscaler Notification Framework is disabled.",
        "error_description": "Unable to send notification because Zscaler Notification framework is disabled.",
        "recommended_action": "No action required.",
        "family": "notification",
        "severity_hint": "info",
    },
]


# =====================================================================
# Aggregated exports
# =====================================================================

ERRORS: List[ZdxRemediationError] = (
    _WORKFLOW + _TASK + _SCRIPT + _LOG_FETCH + _NOTIFICATION
)

# Code -> first row (chip-display path).
# SCRIPT_CERT_VALIDATION_FAILED appears twice — first row wins for
# chip; full list is in ERRORS_BY_CODE_ALL.
ERRORS_BY_CODE: Dict[str, ZdxRemediationError] = {}
ERRORS_BY_CODE_ALL: Dict[str, List[ZdxRemediationError]] = {}
for _row in ERRORS:
    _c = _row["code"]
    ERRORS_BY_CODE_ALL.setdefault(_c, []).append(_row)
    if _c not in ERRORS_BY_CODE:
        ERRORS_BY_CODE[_c] = _row

# Documented error-message lookup (each message string is unique per
# documentation, including across the two SCRIPT_CERT_VALIDATION_FAILED rows).
ERRORS_BY_MESSAGE: Dict[str, ZdxRemediationError] = {
    r["error_message"]: r for r in ERRORS
}


def get_zdx_remediation_error(key: str) -> Optional[ZdxRemediationError]:
    """Return the ZDX Remediation error row for ``key``, or None.

    Tries code match first (ZUPM_WORKFLOW_E_CODE_*), then exact
    documented message match.
    """
    if key is None:
        return None
    k = str(key).strip()
    if k in ERRORS_BY_CODE:
        return ERRORS_BY_CODE[k]
    if k in ERRORS_BY_MESSAGE:
        return ERRORS_BY_MESSAGE[k]
    return None


def get_zdx_remediation_error_all(code: str) -> List[ZdxRemediationError]:
    """Return every row for ``code`` — only matters for
    SCRIPT_CERT_VALIDATION_FAILED which has 2 rows."""
    if code is None:
        return []
    return list(ERRORS_BY_CODE_ALL.get(str(code).strip(), ()))


def zdx_remediation_error_severity(key: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZDX Remediation error."""
    row = get_zdx_remediation_error(key)
    if row is None:
        return default
    return row.get("severity_hint", default)


# =====================================================================
# Self-check at import time
# =====================================================================

assert len(_WORKFLOW) == 12, f"Workflow count drifted: {len(_WORKFLOW)}"
assert len(_TASK) == 3, f"Task count drifted: {len(_TASK)}"
# 18 = 17 distinct codes + 1 duplicate row for SCRIPT_CERT_VALIDATION_FAILED
# (the documentation lists "Script certificate verification failure" and "Script
# signature validation failure" against the same code). My original
# Phase 8c count said 17 — that was the distinct-code count, not the
# row count. The asserts check rows, so the correct number is 18.
# Fixed 2026-06-17 after a real bundle import surfaced the drift.
assert len(_SCRIPT) == 18, f"Script count drifted: {len(_SCRIPT)}"
assert len(_LOG_FETCH) == 3, f"Log fetch count drifted: {len(_LOG_FETCH)}"
assert len(_NOTIFICATION) == 5, f"Notification count drifted: {len(_NOTIFICATION)}"
assert len(ERRORS) == 41, f"Total row count drifted: {len(ERRORS)}"
# SCRIPT_CERT_VALIDATION_FAILED appears twice (verified)
assert len(ERRORS_BY_CODE_ALL["ZUPM_WORKFLOW_E_CODE_SCRIPT_CERT_VALIDATION_FAILED"]) == 2, \
    "SCRIPT_CERT_VALIDATION_FAILED should have 2 documented messages"
