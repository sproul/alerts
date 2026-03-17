#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alert__common_importance import (
    dispatch_alert,
    get_important_senders,
    get_insignificance_regexes,
    get_significance_regexes,
    match_any_regex,
)

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
except ImportError:
    print("FAIL slack_sdk is required. Run: pip install slack_sdk", file=sys.stderr)
    sys.exit(1)

SLACK_TOKEN_ENV = "SLACK_ALERT_TOKEN"
SLACK_APP_ADMIN_TOKEN_ENV = "SLACK_ALERT_ADMIN_TOKEN"
SEEN_FILE = Path.home() / ".slack_important_seen.json"
MAX_MESSAGES_PER_CONVERSATION = 50

IMPORTANT_SENDERS = get_important_senders()
INSIGNIFICANCE_REGEXES = get_insignificance_regexes()
SIGNIFICANCE_REGEXES = get_significance_regexes()


@dataclass(frozen=True)
class Conversation:
    channel_id: str
    kind: str
    label: str
    dm_user_id: str | None = None


def exit_with_slack_error(action: str, error: SlackApiError) -> None:
    message = error.response["error"] if error.response else str(error)
    print(f"FAIL Slack API {action} failed: {message}", file=sys.stderr)
    sys.exit(1)


def build_slack_app_manifest() -> dict[str, Any]:
    return {
        "display_information": {"name": "alert__slack_app"},
        "features": {
            "bot_user": {
                "display_name": "alert__slack_bot",
                "always_online": False,
            }
        },
        "oauth_config": {
            "scopes": {
                "bot": [
                    "channels:history",
                    "groups:history",
                    "im:history",
                    "mpim:history",
                    "channels:read",
                    "groups:read",
                    "im:read",
                    "mpim:read",
                    "users:read",
                ]
            }
        },
        "settings": {
            "event_subscriptions": {"bot_events": []},
            "interactivity": {"is_enabled": False},
            "org_deploy_enabled": False,
            "socket_mode_enabled": False,
            "token_rotation_enabled": False,
        },
    }


def get_slack_token() -> str:
    token = os.environ.get(SLACK_TOKEN_ENV)
    if not token:
        print(f"FAIL {SLACK_TOKEN_ENV} environment variable is required", file=sys.stderr)
        sys.exit(1)
    return token


def install_slack_app() -> None:
    admin_token = os.environ.get(SLACK_APP_ADMIN_TOKEN_ENV)
    if not admin_token:
        print(
            f"FAIL {SLACK_APP_ADMIN_TOKEN_ENV} environment variable is required for --install-app",
            file=sys.stderr,
        )
        sys.exit(1)
    manifest = build_slack_app_manifest()
    client = WebClient(token=admin_token)
    try:
        response = client.apps_manifest_create(manifest=manifest)
    except SlackApiError as error:  # pragma: no cover - depends on Slack
        exit_with_slack_error("apps.manifest.create", error)
    app_id = response.get("app_id")
    app_url = response.get("app_url")
    if app_id and app_url:
        print(
            f"OK Slack app alert__slack_app created with app_id {app_id}. Visit {app_url} to complete installation."
        )
    else:
        print("OK Slack app manifest submitted; review Slack admin to finalize installation.")


def build_slack_client() -> WebClient:
    return WebClient(token=get_slack_token())


def load_seen_message_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        print(f"FAIL Seen file {path} must contain a JSON list", file=sys.stderr)
        sys.exit(1)
    return {str(item) for item in data}


def save_seen_message_ids(path: Path, seen_ids: set[str]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sorted(seen_ids), handle)


def fetch_self_user_id(client: WebClient) -> str:
    try:
        response = client.auth_test()
    except SlackApiError as error:  # pragma: no cover - depends on Slack
        exit_with_slack_error("auth.test", error)
    user_id = response.get("user_id")
    if not user_id:
        print("FAIL Slack auth.test did not return user_id", file=sys.stderr)
        sys.exit(1)
    return user_id


def derive_user_display_name(member: dict[str, Any]) -> str:
    profile = member.get("profile") or {}
    candidate_keys = (
        "display_name_normalized",
        "display_name",
        "real_name_normalized",
        "real_name",
    )
    for key in candidate_keys:
        name = profile.get(key)
        if name:
            return name
    return member.get("name") or member.get("id") or "unknown user"


def build_user_directory(client: WebClient) -> dict[str, str]:
    directory: dict[str, str] = {}
    cursor: str | None = None
    while True:
        try:
            response = client.users_list(limit=200, cursor=cursor)
        except SlackApiError as error:  # pragma: no cover - depends on Slack
            exit_with_slack_error("users.list", error)
        for member in response.get("members", []):
            if member.get("deleted") or member.get("is_bot"):
                continue
            user_id = member.get("id")
            if not user_id:
                continue
            directory[user_id] = derive_user_display_name(member)
        cursor = response.get("response_metadata", {}).get("next_cursor") or ""
        if not cursor:
            break
    return directory


def classify_conversation(
    channel: dict[str, Any],
    user_directory: dict[str, str],
) -> Conversation | None:
    channel_id = channel.get("id")
    if not channel_id:
        return None
    if channel.get("is_im"):
        user_id = channel.get("user")
        label = f"DM with {user_directory.get(user_id, user_id or 'unknown user')}"
        return Conversation(channel_id=channel_id, kind="im", label=label, dm_user_id=user_id)
    if channel.get("is_mpim"):
        label = channel.get("name") or f"Group DM {channel_id}"
        return Conversation(channel_id=channel_id, kind="mpim", label=label)
    name = channel.get("name")
    if name:
        return Conversation(channel_id=channel_id, kind="channel", label=f"#{name}")
    return Conversation(channel_id=channel_id, kind="channel", label=channel_id)


def fetch_conversations(
    client: WebClient,
    user_directory: dict[str, str],
) -> list[Conversation]:
    conversations: list[Conversation] = []
    cursor: str | None = None
    while True:
        try:
            response = client.conversations_list(
                types="im,mpim,public_channel,private_channel",
                limit=200,
                cursor=cursor,
            )
        except SlackApiError as error:  # pragma: no cover - depends on Slack
            exit_with_slack_error("conversations.list", error)
        for channel in response.get("channels", []):
            if channel.get("is_archived"):
                continue
            conversation = classify_conversation(channel, user_directory)
            if conversation:
                conversations.append(conversation)
        cursor = response.get("response_metadata", {}).get("next_cursor") or ""
        if not cursor:
            break
    return conversations


def fetch_recent_messages(client: WebClient, channel_id: str) -> list[dict[str, Any]]:
    try:
        response = client.conversations_history(
            channel=channel_id,
            limit=MAX_MESSAGES_PER_CONVERSATION,
            inclusive=True,
        )
    except SlackApiError as error:  # pragma: no cover - depends on Slack
        exit_with_slack_error(f"conversations.history for {channel_id}", error)
    return response.get("messages", [])


def build_message_key(channel_id: str, message: dict[str, Any]) -> str:
    ts = message.get("ts")
    if not ts:
        print(f"FAIL Slack message missing ts in {channel_id}", file=sys.stderr)
        sys.exit(1)
    return f"{channel_id}:{ts}"


def mentions_self(text: str, self_user_id: str) -> bool:
    return f"<@{self_user_id}>" in text


def resolve_sender_info(
    message: dict[str, Any],
    user_directory: dict[str, str],
) -> tuple[str | None, str | None]:
    user_id = message.get("user")
    if user_id:
        return user_id, user_directory.get(user_id)
    profile = message.get("user_profile") or {}
    name = profile.get("display_name") or profile.get("real_name")
    if name:
        return None, name
    return None, None


def build_sender_descriptor(sender_id: str | None, sender_name: str | None) -> str:
    if sender_name:
        return sender_name
    if sender_id:
        return sender_id
    return "unknown sender"


def resolve_message_text(message: dict[str, Any]) -> str:
    text_parts: list[str] = []
    text = message.get("text")
    if text:
        text_parts.append(text)
    for attachment in message.get("attachments", []) or []:
        for key in ("text", "fallback", "title"):
            value = attachment.get(key)
            if value:
                text_parts.append(value)
    return "\n".join(part for part in text_parts if part).strip()


def should_alert_for_significance(text: str) -> bool:
    if not text:
        return False
    if not match_any_regex(SIGNIFICANCE_REGEXES, [text]):
        return False
    return not match_any_regex(INSIGNIFICANCE_REGEXES, [text])


def is_suppressed(text: str) -> bool:
    return bool(text and match_any_regex(INSIGNIFICANCE_REGEXES, [text]))


def match_important_sender_name(sender_name: str | None) -> str | None:
    if not sender_name:
        return None
    normalized = sender_name.lower()
    for important in IMPORTANT_SENDERS:
        if important.lower() in normalized:
            return important
    return None


def send_alert_payload(
    reason: str,
    conversation: Conversation,
    sender_desc: str,
    text: str,
) -> int:
    summary = f"slack message {reason} from {sender_desc} in {conversation.label}"
    body = (
        f"Conversation: {conversation.label}\n"
        f"Reason: {reason}\n"
        f"Sender: {sender_desc}\n\n{text}"
    )
    if dispatch_alert(summary, body):
        print(
            f"OK Alert sent for Slack message {reason} from {sender_desc} in {conversation.label}"
        )
        return 1
    print(
        f"FAIL Could not send alert for Slack message {reason} from {sender_desc} in {conversation.label}",
        file=sys.stderr,
    )
    return 0


def process_single_message(
    message: dict[str, Any],
    conversation: Conversation,
    user_directory: dict[str, str],
    self_user_id: str,
    message_key: str,
    new_seen_ids: set[str],
) -> int:
    if message.get("subtype") or message.get("bot_id"):
        new_seen_ids.add(message_key)
        return 0
    sender_id, sender_name = resolve_sender_info(message, user_directory)
    if sender_id == self_user_id:
        new_seen_ids.add(message_key)
        return 0
    text = resolve_message_text(message)
    if not text:
        new_seen_ids.add(message_key)
        return 0
    if conversation.kind == "channel" and not mentions_self(text, self_user_id):
        new_seen_ids.add(message_key)
        return 0
    sender_desc = build_sender_descriptor(sender_id, sender_name)
    alerts = 0
    if should_alert_for_significance(text):
        alerts += send_alert_payload("matching significance pattern", conversation, sender_desc, text)
    else:
        matched_name = match_important_sender_name(sender_name)
        if matched_name and not is_suppressed(text):
            alerts += send_alert_payload(f"from {matched_name}", conversation, sender_desc, text)
    new_seen_ids.add(message_key)
    return alerts


def process_conversation(
    client: WebClient,
    conversation: Conversation,
    user_directory: dict[str, str],
    self_user_id: str,
    seen_ids: set[str],
    new_seen_ids: set[str],
) -> int:
    messages = fetch_recent_messages(client, conversation.channel_id)
    alerts = 0
    for message in messages:
        message_key = build_message_key(conversation.channel_id, message)
        if message_key in seen_ids:
            continue
        alerts += process_single_message(
            message,
            conversation,
            user_directory,
            self_user_id,
            message_key,
            new_seen_ids,
        )
    return alerts


def check_slack_messages() -> int:
    client = build_slack_client()
    seen_ids = load_seen_message_ids(SEEN_FILE)
    new_seen_ids = set(seen_ids)
    self_user_id = fetch_self_user_id(client)
    user_directory = build_user_directory(client)
    conversations = fetch_conversations(client, user_directory)
    alerts_sent = 0
    for conversation in conversations:
        alerts_sent += process_conversation(
            client,
            conversation,
            user_directory,
            self_user_id,
            seen_ids,
            new_seen_ids,
        )
    save_seen_message_ids(SEEN_FILE, new_seen_ids)
    return alerts_sent


def main() -> None:
    parser = argparse.ArgumentParser(description="Slack alert checker for important senders")
    parser.add_argument(
        "--install-app",
        action="store_true",
        help=(
            "Create the alert__slack_app using Slack manifest API. Requires admin token in "
            f"{SLACK_APP_ADMIN_TOKEN_ENV}."
        ),
    )
    args = parser.parse_args()

    if args.install_app:
        install_slack_app()
        return

    try:
        alerts = check_slack_messages()
        if alerts > 0:
            print(f"OK Sent {alerts} alert(s) for Slack messages")
        else:
            print("OK No new significant Slack messages")
    except Exception as error:  # noqa: BLE001 - want diagnostic content
        print(f"FAIL {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
