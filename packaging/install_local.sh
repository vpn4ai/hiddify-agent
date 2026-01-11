#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MASTER_URL="${MASTER_URL:-http://127.0.0.1:9100}"
AGENT_ID="${AGENT_ID:-}"
NODE_NAME="${NODE_NAME:-local-exit-node}"
NODE_IP="${NODE_IP:-127.0.0.1}"
REGION="${REGION:-local}"

if [ -z "$AGENT_ID" ]; then
  echo "AGENT_ID is required" >&2
  exit 1
fi

install -m 0755 "$ROOT_DIR/hiddify-agent" /usr/local/bin/hiddify-agent

mkdir -p /etc/hiddify-agent /var/lib/hiddify-agent /etc/sing-box

cat >/etc/hiddify-agent/config.yaml <<EOF
master_url: "$MASTER_URL"
agent_id: "$AGENT_ID"
node_name: "$NODE_NAME"
node_ip: "$NODE_IP"
region: "$REGION"
token_path: "/var/lib/hiddify-agent/token.json"
singbox_config_path: "/etc/sing-box/config.json"
singbox_systemd_unit: "sing-box.service"
v2rayapi_address: "127.0.0.1:8080"
heartbeat_interval_seconds: 60
traffic_report_interval_seconds: 600
EOF

if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.app/install.sh | sh -s -- --version 1.12.14
fi

install -m 0644 "$ROOT_DIR/packaging/systemd/sing-box.service" /etc/systemd/system/sing-box.service
install -m 0644 "$ROOT_DIR/packaging/systemd/hiddify-agent.service" /etc/systemd/system/hiddify-agent.service

systemctl daemon-reload
systemctl enable --now sing-box.service
systemctl enable --now hiddify-agent.service

systemctl --no-pager -l status hiddify-agent.service || true
systemctl --no-pager -l status sing-box.service || true
