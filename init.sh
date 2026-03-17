#!/bin/bash
set -euo pipefail

VENV_PATH="$HOME/dp/venv_qr311ac"
PYTHON_BIN="$VENV_PATH/bin/python"

if [ ! -d "$VENV_PATH" ]; then
  echo "FAIL Expected Python virtualenv at $VENV_PATH" 1>&2
  exit 1
fi

if [ ! -x "$PYTHON_BIN" ]; then
  echo "FAIL Python binary not found at $PYTHON_BIN" 1>&2
  exit 1
fi

# shellcheck source=/dev/null
source "$VENV_PATH/bin/activate"

REQUIRED_PACKAGES=(
  google-auth
  google-auth-oauthlib
  google-api-python-client
  slack_sdk
)

echo "OK Installing required Python packages"
"$PYTHON_BIN" -m pip install --upgrade "${REQUIRED_PACKAGES[@]}"

environment_instructions=$(cat <<'EOF'
OK Automated setup finished.

Manual steps to complete deployment:

1. Gmail API credentials
   - Visit https://console.cloud.google.com/ and ensure the Gmail API is enabled for your project.
   - Download the OAuth desktop credentials JSON and save it as $HOME/.gmail_credentials.json.
   - Run alerts/alert__gmail_check_important_senders.py once interactively to authorize and create $HOME/.gmail_token.json.

2. Slack app provisioning
   - Obtain a Slack admin token with permissions to create apps and export it: export SLACK_ALERT_ADMIN_TOKEN="xoxa-...".
   - Run: python3 alerts/alert__slack_check_important_senders.py --install-app
   - Follow the Slack-provided URL to review and install the app in each workspace.

3. Runtime configuration
   - Export the issued bot token: export SLACK_ALERT_TOKEN="xoxb-..." (ensure the token is available wherever the scripts run).
   - Confirm cron or alert launchers reference alerts/alert__gmail_check_important_senders.py and alerts/alert__slack_check_important_senders.py.
   - Verify that alert.sh is executable and reachable at $dp/git/bin/alert.sh.

4. Validation
   - Send a test Gmail and Slack message matching significance rules to confirm alerts fire.
   - Review logs for messages prefixed with "OK" or "FAIL" to confirm healthy operation.
EOF
)

echo "$environment_instructions"
exit
bash -x $dp/git/alerts/init.sh