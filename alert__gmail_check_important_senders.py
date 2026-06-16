#!/usr/bin/env python3

import argparse
import base64
import json
import re
import sys
import warnings
from datetime import datetime
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path
from typing import Callable, Iterable, Iterator, Pattern

from urllib3.exceptions import NotOpenSSLWarning

from alert__common_importance import (
    dispatch_alert,
    get_important_senders,
    get_insignificance_regexes,
    get_significance_regexes,
    match_any_regex,
)


IMPORTANT_SENDERS = get_important_senders()
INSIGNIFICANCE_REGEXES = get_insignificance_regexes()
SIGNIFICANCE_REGEXES = get_significance_regexes()

"""
Check Gmail for unread messages from important senders.
Calls alert.sh when important mail is found.

Usage: alert__gmail_check_important_senders.py

Requires:
- Gmail API credentials in ~/.gmail_credentials.json
- Token will be stored in ~/.gmail_token.json

First-time setup:
1. Go to https://console.cloud.google.com/
2. Create a project and enable Gmail API

    To create a Google Cloud project:
    
    Go to https://console.cloud.google.com/
    Click the project dropdown at the top left (next to "Google Cloud")
    Click New Project in the popup
    Enter a project name (e.g., "Gmail Alert Checker")
    Click Create
    Wait a few seconds for it to be created, then select it from the dropdown
    Then enable Gmail API:
    
    Go to APIs & Services → Library (left sidebar)
    Search for "Gmail API"
    Click on it and click Enable
    Then create OAuth credentials:
    
    Go to APIs & Services → Credentials
    Click Configure Consent Screen if prompted
    Choose External (unless you have a Google Workspace org)
    Fill in app name, user support email, developer email
    Click through the rest (scopes, test users) - add your Gmail as a test user
    Go back to Credentials → Create Credentials → OAuth client ID
    Select Desktop app
    Download the JSON and save as $HOME/.gmail_credentials.json

3. Create OAuth 2.0 credentials (Desktop app)
4. Download credentials.json and save as ~/.gmail_credentials.json
5. Run this script once interactively to authorize


"""

warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

CREDENTIALS_FILE = Path.home() / ".gmail_credentials.json"
TOKEN_FILE = Path.home() / ".gmail_token.json"
SEEN_FILE_PATH = Path.home() / ".gmail_important_seen.json"

DEBUG_MODE = False
IGNORE_SEEN_MODE = False


def debug_log(message: str) -> None:
    if DEBUG_MODE:
        print(f"OK DEBUG {message}")


def remove_invalid_token_file():
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        print("OK Removed invalid Gmail token; reauthorization required", file=sys.stderr)


def is_invalid_grant_error(error: Exception) -> bool:
    text = str(error)
    return "invalid_grant" in text or "Invalid Credentials" in text


def load_seen_message_ids() -> set[str]:
    if IGNORE_SEEN_MODE:
        debug_log("Ignoring seen message cache due to CLI option")
        return set()
    if not SEEN_FILE_PATH.exists():
        debug_log(f"Seen file {SEEN_FILE_PATH} does not exist")
        return set()
    with open(SEEN_FILE_PATH, "r", encoding="utf-8") as handle:
        cached_ids = set(json.load(handle))
    debug_log(f"Loaded {len(cached_ids)} seen message ids from {SEEN_FILE_PATH}")
    return cached_ids


def save_seen_message_ids(seen_ids: set[str]) -> None:
    if IGNORE_SEEN_MODE:
        debug_log("Not persisting seen message ids due to CLI ignore option")
        return
    with open(SEEN_FILE_PATH, "w", encoding="utf-8") as handle:
        json.dump(sorted(seen_ids), handle)
    debug_log(f"Persisted {len(seen_ids)} seen message ids to {SEEN_FILE_PATH}")


def collect_pattern_matches(
    patterns: Iterable[Pattern[str]],
    field_values: dict[str, str],
) -> list[tuple[Pattern[str], str, int]]:
    matches: list[tuple[Pattern[str], str, int]] = []
    for pattern in patterns:
        for field_name, value in field_values.items():
            if not value:
                continue
            match = pattern.search(value)
            if match:
                matches.append((pattern, field_name, match.start()))
                break
    return matches


def is_google_voice_notification(from_header: str, subject: str) -> bool:
    header_lower = (from_header or "").lower()
    subject_lower = (subject or "").lower()
    return "txt.voice.google.com" in header_lower or subject_lower.startswith("new text message from ")


def should_override_insignificance_for_google_voice(
    insignificance_matches: list[tuple[Pattern[str], str, int]],
    from_header: str,
    subject: str,
    snippet: str,
) -> bool:
    if not insignificance_matches:
        return False
    if not is_google_voice_notification(from_header, subject):
        return False
    snippet_value = snippet or ""
    if not snippet_value:
        return False
    for pattern, field_name, match_start in insignificance_matches:
        if field_name != "snippet":
            continue
        if "your account help center help forum" not in pattern.pattern.lower():
            continue
        prefix = snippet_value[:match_start].strip()
        prefix_without_brand = prefix.replace("Google Voice", "").strip()
        if any(char.isalnum() for char in prefix_without_brand):
            return True
    return False


def get_gmail_service():
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        from google.auth.exceptions import RefreshError
        from googleapiclient.discovery import build
    except ImportError:
        print("FAIL Required packages not installed. Run:", file=sys.stderr)
        print("  pip install google-auth google-auth-oauthlib google-api-python-client", file=sys.stderr)
        sys.exit(1)

    scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    creds = None

    token_should_be_saved = False

    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), scopes)

    needs_authorization = not creds or not creds.valid

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            needs_authorization = False
            token_should_be_saved = True
        except RefreshError as refresh_error:
            if is_invalid_grant_error(refresh_error):
                remove_invalid_token_file()
                creds = None
                needs_authorization = True
            else:
                raise
        except Exception as refresh_error:
            if is_invalid_grant_error(refresh_error):
                remove_invalid_token_file()
                creds = None
                needs_authorization = True
            else:
                raise

    if needs_authorization:
        if not CREDENTIALS_FILE.exists():
            print(f"FAIL Credentials file not found: {CREDENTIALS_FILE}", file=sys.stderr)
            print("Download OAuth credentials from Google Cloud Console", file=sys.stderr)
            sys.exit(1)
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), scopes)
        creds = flow.run_local_server(port=0)
        token_should_be_saved = True

    if token_should_be_saved or not TOKEN_FILE.exists():
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def decode_mime_header(raw_value: str) -> str:
    if not raw_value:
        return ""
    try:
        fragments = decode_header(raw_value)
    except Exception:
        return raw_value
    decoded_parts: list[str] = []
    for fragment, encoding in fragments:
        if isinstance(fragment, bytes):
            codec = encoding or "utf-8"
            try:
                decoded_parts.append(fragment.decode(codec, errors="replace"))
            except Exception:
                decoded_parts.append(fragment.decode("utf-8", errors="replace"))
        else:
            decoded_parts.append(fragment)
    return "".join(decoded_parts)


def extract_sender_name(from_header):
    decoded = decode_mime_header(from_header)
    name, email_address = parseaddr(decoded)
    if name:
        return name.strip().strip('"')
    if "<" in decoded:
        return decoded.split("<")[0].strip().strip('"')
    if email_address:
        return email_address
    return decoded.strip()


def extract_subject(headers):
    for header in headers:
        if header["name"].lower() == "subject":
            return decode_mime_header(header["value"])
    return "(no subject)"


def normalize_sender_name(name):
    normalized = name.strip()
    if normalized.endswith(" (SMS)"):
        normalized = normalized[:-6]
    return normalized


def is_important_sender(from_header):
    sender_name = extract_sender_name(from_header)
    normalized_sender = normalize_sender_name(sender_name)
    for important in IMPORTANT_SENDERS:
        if important.lower() in normalized_sender.lower():
            return True, important
    return False, None


def is_suppressed_message(from_header, subject, snippet):
    field_map = {
        "from": from_header or "",
        "subject": subject or "",
        "snippet": snippet or "",
    }
    matches = collect_pattern_matches(INSIGNIFICANCE_REGEXES, field_map)
    if matches and should_override_insignificance_for_google_voice(matches, from_header, subject, snippet):
        debug_log("Google Voice insignificance override applied; not suppressing message")
        return False
    return bool(matches)


def is_significant_message(from_header, subject, snippet):
    field_map = {
        "from": from_header or "",
        "subject": subject or "",
        "snippet": snippet or "",
    }
    matches = collect_pattern_matches(SIGNIFICANCE_REGEXES, field_map)
    return bool(matches)


def send_alert(sender_name, subject, message_snippet):
    summary = f"mail from {sender_name}: \"{subject}\""
    body = f"From: {sender_name}\nSubject: {subject}\n\n{message_snippet}"
    return dispatch_alert(summary, body)


def call_gmail_with_reauth(operation: Callable):
    service = get_gmail_service()
    try:
        return operation(service)
    except Exception as error:  # noqa: BLE001 - we must inspect the error content
        if is_invalid_grant_error(error):
            remove_invalid_token_file()
            service = get_gmail_service()
            return operation(service)
        raise


def fetch_unread_messages(service):
    response = service.users().messages().list(
        userId="me",
        q="is:unread",
        maxResults=50
    ).execute()
    return response.get("messages", [])


def fetch_message_metadata(service, message_id):
    return service.users().messages().get(
        userId="me",
        id=message_id,
        format="metadata",
        metadataHeaders=["From", "Subject"]
    ).execute()


def process_single_message(service, message_info, seen_ids, new_seen_ids):
    msg_id = message_info["id"]
    if msg_id in seen_ids:
        debug_log(f"Skipping message {msg_id} (already seen)")
        return 0

    message = fetch_message_metadata(service, msg_id)
    headers = message.get("payload", {}).get("headers", [])
    from_header = ""
    for header in headers:
        if header["name"].lower() == "from":
            from_header = header["value"]
            break

    subject = extract_subject(headers)
    snippet = message.get("snippet", "")

    if DEBUG_MODE:
        debug_log(
            "Processing message {}\n  From: {}\n  Subject: {}\n  Snippet: {}".format(
                msg_id,
                from_header,
                subject,
                snippet,
            )
        )

    if is_significant_message(from_header, subject, snippet):
        if is_suppressed_message(from_header, subject, snippet):
            debug_log(f"Message {msg_id} matches significance and insignificance; suppressed")
            new_seen_ids.add(msg_id)
            return 0
        sender_name = extract_sender_name(from_header) or "Unknown sender"
        if send_alert(sender_name, subject, snippet):
            print(f"OK Alert sent for mail matching significance pattern from {sender_name}: {subject}")
        else:
            print(
                f"FAIL Could not send alert for mail matching significance pattern from {sender_name}",
                file=sys.stderr,
            )
            new_seen_ids.add(msg_id)
            return 0
        new_seen_ids.add(msg_id)
        return 1

    is_important, matched_name = is_important_sender(from_header)
    if is_important:
        if is_suppressed_message(from_header, subject, snippet):
            debug_log(f"Message {msg_id} from {matched_name} suppressed by insignificance patterns")
            new_seen_ids.add(msg_id)
            return 0
        if send_alert(matched_name, subject, snippet):
            print(f"OK Alert sent for mail from {matched_name}: {subject}")
        else:
            print(f"FAIL Could not send alert for mail from {matched_name}", file=sys.stderr)
            new_seen_ids.add(msg_id)
            return 0
        new_seen_ids.add(msg_id)
        return 1

    new_seen_ids.add(msg_id)
    return 0


def process_unread_messages(service):
    seen_ids = load_seen_message_ids()
    new_seen_ids = set(seen_ids)
    alerts_sent = 0

    messages = fetch_unread_messages(service)
    if not messages:
        return 0

    for msg_info in messages:
        alerts_sent += process_single_message(service, msg_info, seen_ids, new_seen_ids)

    save_seen_message_ids(new_seen_ids)
    return alerts_sent


def check_for_important_mail():
    return call_gmail_with_reauth(process_unread_messages)


def build_attachment_query(sender: str) -> str:
    sender_value = sender.strip()
    already_quoted = sender_value.startswith('"') and sender_value.endswith('"')
    if " " in sender_value and not already_quoted:
        sender_value = f'"{sender_value}"'
    return f"from:{sender_value} has:attachment"


def fetch_all_message_ids(service, query: str) -> list[str]:
    message_ids: list[str] = []
    page_token = None
    while True:
        response = service.users().messages().list(
            userId="me", q=query, maxResults=100, pageToken=page_token
        ).execute()
        message_ids.extend(message["id"] for message in response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return message_ids


def format_message_date(message: dict) -> str:
    internal_date_ms = message.get("internalDate")
    if not internal_date_ms:
        return "0000-00-00"
    timestamp_seconds = int(internal_date_ms) / 1000
    return datetime.fromtimestamp(timestamp_seconds).strftime("%Y-%m-%d")


def iter_attachment_parts(payload: dict) -> Iterator[tuple[str, str]]:
    for part in payload.get("parts", []):
        yield from iter_attachment_parts(part)
    filename = payload.get("filename")
    body = payload.get("body", {})
    attachment_id = body.get("attachmentId")
    if filename and attachment_id:
        yield filename, attachment_id


def sanitize_filename(filename: str) -> str:
    cleaned = re.sub(r"[/\\\x00]", "_", filename).strip()
    return cleaned or "attachment"


def build_unique_attachment_path(output_dir: Path, date_prefix: str, filename: str) -> Path:
    safe_name = sanitize_filename(filename)
    candidate = output_dir / f"{date_prefix}_{safe_name}"
    counter = 2
    while candidate.exists():
        candidate = output_dir / f"{date_prefix}_{candidate.stem}__{counter}{candidate.suffix}"
        counter += 1
    return candidate


def download_attachment_data(service, message_id: str, attachment_id: str) -> bytes:
    attachment = service.users().messages().attachments().get(
        userId="me", messageId=message_id, id=attachment_id
    ).execute()
    return base64.urlsafe_b64decode(attachment["data"])


def save_message_attachments(service, message_id: str, output_dir: Path) -> int:
    message = service.users().messages().get(
        userId="me", id=message_id, format="full"
    ).execute()
    date_prefix = format_message_date(message)
    saved_count = 0
    for filename, attachment_id in iter_attachment_parts(message.get("payload", {})):
        data = download_attachment_data(service, message_id, attachment_id)
        target_path = build_unique_attachment_path(output_dir, date_prefix, filename)
        target_path.write_bytes(data)
        print(f"OK Saved {target_path}")
        saved_count += 1
    return saved_count


def gather_attachments_from_sender(service, sender: str, output_dir: Path) -> int:
    query = build_attachment_query(sender)
    debug_log(f"Gathering attachments with query: {query}")
    message_ids = fetch_all_message_ids(service, query)
    print(f"OK Found {len(message_ids)} message(s) with attachments from {sender}")
    output_dir.mkdir(parents=True, exist_ok=True)
    total_saved = 0
    for message_id in message_ids:
        total_saved += save_message_attachments(service, message_id, output_dir)
    return total_saved


def default_attachments_dir(sender: str) -> Path:
    safe_sender = re.sub(r"[^A-Za-z0-9._-]+", "_", sender.strip()).strip("_") or "sender"
    return Path.cwd() / f"gmail_attachments_{safe_sender}"


def run_attachment_gathering(args: argparse.Namespace) -> int:
    if args.attachments_dir:
        output_dir = Path(args.attachments_dir)
    else:
        output_dir = default_attachments_dir(args.gather_attachments_from)
    total_saved = call_gmail_with_reauth(
        lambda service: gather_attachments_from_sender(
            service, args.gather_attachments_from, output_dir
        )
    )
    if total_saved > 0:
        print(f"OK Saved {total_saved} attachment(s) to {output_dir}")
    else:
        print(f"OK No attachments found from {args.gather_attachments_from}")
    return total_saved


def parse_cli_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check Gmail for important messages")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--ignore-seen",
        action="store_true",
        help="Ignore cached seen message IDs for this run",
    )
    parser.add_argument(
        "--clear-seen",
        action="store_true",
        help="Delete the seen message cache before processing",
    )
    parser.add_argument(
        "--seen-file",
        type=str,
        default=str(SEEN_FILE_PATH),
        help="Override path to the seen message cache file",
    )
    parser.add_argument(
        "--gather_attachments_from",
        type=str,
        default=None,
        metavar="USER",
        help="Download every attachment ever emailed from USER (name or address), "
        "saving each with a YYYY-MM-DD date prefix; skips the normal unread-mail check",
    )
    parser.add_argument(
        "--attachments-dir",
        type=str,
        default=None,
        help="Destination directory for --gather_attachments_from "
        "(default: ./gmail_attachments_<sender> in the current directory)",
    )
    return parser.parse_args()


def configure_runtime_from_args(args: argparse.Namespace) -> None:
    global DEBUG_MODE
    global IGNORE_SEEN_MODE
    global SEEN_FILE_PATH

    if args.debug:
        DEBUG_MODE = True
        debug_log("Debug logging enabled")

    if args.ignore_seen:
        IGNORE_SEEN_MODE = True
        debug_log("Ignoring seen messages for this execution")

    if args.seen_file:
        SEEN_FILE_PATH = Path(args.seen_file)
        debug_log(f"Using seen file at {SEEN_FILE_PATH}")

    if args.clear_seen:
        if SEEN_FILE_PATH.exists():
            SEEN_FILE_PATH.unlink()
            print(f"OK Cleared seen cache at {SEEN_FILE_PATH}")
        else:
            print(f"OK Seen cache {SEEN_FILE_PATH} already absent")

    if DEBUG_MODE:
        debug_log("Important senders configured:")
        for sender in IMPORTANT_SENDERS:
            debug_log(f"  sender: {sender}")
        debug_log("Significance patterns configured:")
        for pattern in SIGNIFICANCE_REGEXES:
            debug_log(f"  significance regex: {pattern.pattern}")
        debug_log("Insignificance patterns configured:")
        for pattern in INSIGNIFICANCE_REGEXES:
            debug_log(f"  insignificance regex: {pattern.pattern}")


def main():
    args = parse_cli_arguments()
    configure_runtime_from_args(args)

    if args.gather_attachments_from:
        try:
            run_attachment_gathering(args)
        except Exception as e:
            print(f"FAIL {e}", file=sys.stderr)
            sys.exit(1)
        return

    try:
        alerts = check_for_important_mail()
        if alerts > 0:
            print(f"OK Sent {alerts} alert(s) for important mail")
        else:
            print("OK No new important mail")
    except Exception as e:
        print(f"FAIL {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
