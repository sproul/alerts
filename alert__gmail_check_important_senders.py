#!/usr/bin/env python3

import json
import sys
import warnings
from pathlib import Path
from typing import Callable

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
SEEN_FILE = Path.home() / ".gmail_important_seen.json"


def remove_invalid_token_file():
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        print("OK Removed invalid Gmail token; reauthorization required", file=sys.stderr)


def is_invalid_grant_error(error: Exception) -> bool:
    text = str(error)
    return "invalid_grant" in text or "Invalid Credentials" in text


def load_seen_message_ids():
    if SEEN_FILE.exists():
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_seen_message_ids(seen_ids):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen_ids), f)


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


def extract_sender_name(from_header):
    if "<" in from_header:
        return from_header.split("<")[0].strip().strip('"')
    return from_header.strip()


def extract_subject(headers):
    for header in headers:
        if header["name"].lower() == "subject":
            return header["value"]
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
    fields = [from_header or "", subject or "", snippet or ""]
    return match_any_regex(INSIGNIFICANCE_REGEXES, fields)


def is_significant_message(from_header, subject, snippet):
    fields = [from_header or "", subject or "", snippet or ""]
    return match_any_regex(SIGNIFICANCE_REGEXES, fields)


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

    if is_significant_message(from_header, subject, snippet):
        if is_suppressed_message(from_header, subject, snippet):
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


def main():
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
