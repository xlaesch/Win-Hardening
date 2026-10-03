#!/usr/bin/env bash
# Win-Hardening Elastic stack setup (ES + Kibana, standalone agents).
# Installs the Windows/System integration ingest pipelines DIRECTLY into
# Elasticsearch (no Fleet Server needed), so agents' events arrive ECS-mapped
# and Elastic's polished prebuilt detection rules work as-is.
# Idempotent - safe to re-run. Run once WITH internet (pipeline zips are bundled,
# but the prebuilt rules index benefits from Kibana being able to reach EPR).
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && . ./.env

ES_URL="${ES_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
STACK_IP="${STACK_IP:-$(hostname -I | awk '{print $1}')}"
AUTH="elastic:${ELASTIC_PASSWORD:?ELASTIC_PASSWORD not set - copy .env.example to .env}"

kib() { curl -s -u "$AUTH" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }
es()   { curl -s -u "$AUTH" -H 'Content-Type: application/json' "$@"; }

echo "== waiting for Elasticsearch =="
until es -fs "$ES_URL/_cluster/health" -o /dev/null; do sleep 5; done
echo "== waiting for Kibana =="
until [ "$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$KIBANA_URL/api/status")" = "200" ]; do sleep 5; done

echo "== 30-day trial (unlocks editing prebuilt rules + adding actions; optional) =="
es -X POST "$ES_URL/_license/start_trial?acknowledge=true" -o /dev/null 2>/dev/null || true

echo "== ingest pipelines from bundled integration packages =="
python3 pipelines.py || echo "  !! pipeline install failed - is python3-yaml present? (apt install python3-yaml)"

echo "== detection engine + prebuilt rules =="
kib -X POST "$KIBANA_URL/api/detection_engine/index" -o /dev/null 2>/dev/null || true
kib -X PUT "$KIBANA_URL/api/detection_engine/rules/prepackaged" -d '{}' | jq -r '"  prebuilt installed: \(.rules_installed // 0) updated: \(.rules_updated // 0)"'

echo "== enabling curated CCDC rules =="
RULE_IDS=(
    48b6edfc-079d-4907-b43c-baffa243270d   # multiple logon failures same source
    4e85dc8a-3e41-40d8-bc28-91af7ac6cf60   # logon failures then success
    f9790abf-bd0c-45f9-8b5f-d0b74015e029   # privileged account brute force
    57bc9e8d-9054-472c-9752-4aa91dc4cd49   # Kerberoasting (RC4 TGS)
    e514d8cd-ed15-4011-84e2-d15147e059f1   # pre-auth disabled for user
    d33ea3bf-9a11-463e-bd46-f648f2a0f4b1   # remote service installed
    92a6faf5-78ec-4e25-bea1-73bacc9b59d9   # scheduled task created
    5cd8e1f7-0050-4afc-b2df-904e40b2f5ae   # user added to privileged group
    128468bf-cab1-4637-99ea-fdf3780a4609   # lsass process access
    cde1bafa-9f01-4f43-a872-605b678968b0   # PS hacktool functions
    fddff193-48a3-484d-8d35-90bb3d323a56   # PS kerberos ticket dump
    fe794edd-487f-4a90-b285-3ee54f2af2d3   # defender tampering
)
IDS=""
for rid in "${RULE_IDS[@]}"; do
    id=$(kib "$KIBANA_URL/api/detection_engine/rules?rule_id=$rid" | jq -r '.id // .data[0].id // empty')
    [ -n "$id" ] && IDS="$IDS $id"
done
IDS=$(echo $IDS)
N=$(echo $IDS | wc -w)
JSON=$(echo $IDS | tr ' ' '\n' | jq -R . | jq -sc '.')
[ "$N" -gt 0 ] && kib -X POST "$KIBANA_URL/api/detection_engine/rules/_bulk_action" -d "{\"action\":\"enable\",\"ids\":$JSON}" -o /dev/null
echo "  enabled $N curated rules"

echo "== custom CCDC rules (idempotent by rule_id) =="
while IFS= read -r line; do
    NAME=$(echo "$line" | jq -r '.name')
    RID=$(echo "$line" | jq -r '.rule_id')
    if kib "$KIBANA_URL/api/detection_engine/rules?rule_id=$RID" | jq -e '.id' >/dev/null 2>&1; then
        echo "  rule exists: $NAME"
    else
        kib -X POST "$KIBANA_URL/api/detection_engine/rules" -d "$line" -o /dev/null \
            && echo "  rule created: $NAME" || echo "  !! could not create rule: $NAME"
    fi
done < alerts/custom-rules.ndjson

echo "== data views =="
for pat in "logs-*" "metrics-*" ".alerts-security.alerts-*"; do
    kib -X POST "$KIBANA_URL/api/saved_objects/index-pattern" -d "{\"attributes\":{\"title\":\"$pat\",\"timeFieldName\":\"@timestamp\"}}" -o /dev/null 2>/dev/null || true
done

echo "== webhook connector + actions =="
if [ -n "${WEBHOOK_URL:-}" ]; then
    CONN=$(kib "$KIBANA_URL/api/actions/connectors" | jq -r '.[] | select(.name=="ccdc-webhook") | .id' | head -1)
    if [ -z "$CONN" ]; then
        CONN=$(kib -X POST "$KIBANA_URL/api/actions/connector" -d "{\"name\":\"ccdc-webhook\",\"connector_type_id\":\".webhook\",\"config\":{\"url\":\"$WEBHOOK_URL\",\"method\":\"post\",\"hasHeaders\":false},\"secrets\":{}}" | jq -r '.id')
    fi
    for id in $IDS; do
        kib -X PATCH "$KIBANA_URL/api/detection_engine/rules" -H 'Content-Type: application/json' \
            -d "[{\"id\":\"$id\",\"actions\":[{\"group\":\"default\",\"id\":\"$CONN\",\"action_type_id\":\".webhook\",\"params\":{\"message\":\"{{rule.name}} fired\"}}]}]" -o /dev/null 2>/dev/null || true
    done
    echo "  webhook attached to curated rules: $CONN"
fi

echo
echo "DONE. Stack IP for agents: $STACK_IP"
echo "On each Windows host: fill scripts\\files\\elastic-config.json with"
echo "  ElasticUrl = http://$STACK_IP:9200  (+ elastic / this password)"
echo "then run: .\\Invoke-Harden.ps1 -Modules ElasticAgent"
