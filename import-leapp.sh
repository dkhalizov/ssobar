#!/bin/sh
# One-time import of Leapp AWS SSO sessions into ~/.config/ssobar/config.json (no secrets copied).
set -e
OUT="$HOME/.config/ssobar/config.json"
[ -f "$OUT" ] && [ "$1" != "--force" ] && { echo "$OUT exists (use --force to overwrite)"; exit 1; }
UUID=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}' | tr 'A-Z' 'a-z')
KEY=$(printf %s "$UUID" | shasum -a 256 | cut -d' ' -f1)
mkdir -p "$HOME/.config/ssobar"
openssl enc -d -aes-256-cbc -md md5 -a -A -pass pass:"$KEY" -in "$HOME/.Leapp/Leapp-lock.json" 2>/dev/null \
| /usr/bin/python3 -I -c '
import json, sys, os
d = json.load(sys.stdin)
prof = {p["id"]: p["name"] for p in d["_profiles"]}
sso = d["_awsSsoIntegrations"][0]
order = [p["name"] for p in d["_profiles"] if p["name"] != "default"] + ["default"]
out = []
for s in d["_sessions"]:
    if s.get("type") != "awsSsoRole": continue
    acct, role = s["roleArn"].split(":")[4].split("/")[0], s["roleArn"].split("/")[-1]
    out.append({"name": s["sessionName"], "accountId": acct, "roleName": role, "region": s["region"],
                "profile": prof.get(s["profileId"], "default"), "active": s.get("status") == 2})
out.sort(key=lambda x: (order.index(x["profile"]) if x["profile"] in order else 99, x["name"].lower()))
cfg = {"startUrl": sso["portalUrl"], "ssoRegion": sso["region"], "refreshMinutesBefore": 10, "sessions": out}
path = sys.argv[1]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(cfg, f, indent=2)
print(f"imported {len(out)} sessions -> {path}")
' "$OUT"
