#!/usr/bin/env bash
set -euo pipefail

remote=${1:-yadisk}

read -rp 'ClientID: ' client_id
read -rsp 'Client secret: ' client_secret; echo

url="https://oauth.yandex.ru/authorize?response_type=code&client_id=$client_id"
echo "Откройте ссылку, нажмите \"Разрешить\" и скопируйте код со страницы:"
echo "  $url"
xdg-open "$url" >/dev/null 2>&1 || true
read -rp 'Код подтверждения: ' code
code=$(tr -d '[:space:]' <<<"$code")

response=$(curl -sS -X POST https://oauth.yandex.ru/token \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode "code=$code" \
  --data-urlencode "client_id=$client_id" \
  --data-urlencode "client_secret=$client_secret")

# The rclone Yandex backend expects token_type "OAuth", not the "bearer" Yandex returns.
token=$(python3 -I -c '
import json, sys
from datetime import datetime, timedelta, timezone
r = json.loads(sys.stdin.read())
if "access_token" not in r:
    sys.exit("Яндекс отказал: %s - %s" % (r.get("error"), r.get("error_description")))
expiry = datetime.now(timezone.utc).astimezone() + timedelta(seconds=int(r["expires_in"]))
print(json.dumps({
    "access_token": r["access_token"],
    "token_type": "OAuth",
    "refresh_token": r["refresh_token"],
    "expiry": expiry.isoformat(timespec="seconds"),
}))' <<<"$response")

rclone config update "$remote" client_id "$client_id" client_secret "$client_secret" \
  token "$token" config_refresh_token false --non-interactive >/dev/null

echo "Токен сохранён. Проверка листинга:"
rclone lsd "$remote:" | head -5
