#!/bin/bash
# =============================================================================
# Test suite for Wazuh MCP Server ↔ Elasticsearch integration
# Prerequisites: docker compose -f compose.test.yml up --build -d
# Usage:         bash tests/elasticsearch/run_tests.sh
# =============================================================================

set -euo pipefail

MCP_URL="http://localhost:3000"
ES_URL="http://localhost:9200"

PASS=0
FAIL=0
TOTAL=0

# ---------- helpers ----------
red()   { printf "\033[31m%s\033[0m" "$*"; }
green() { printf "\033[32m%s\033[0m" "$*"; }
bold()  { printf "\033[1m%s\033[0m" "$*"; }

assert_contains() {
  local label="$1" body="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$body" | grep -q "$expected"; then
    echo "  $(green PASS) $label"
    PASS=$((PASS + 1))
  else
    echo "  $(red FAIL) $label  (expected '$expected')"
    echo "       response: $(echo "$body" | head -c 300)"
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local label="$1" body="$2" unexpected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$body" | grep -q "$unexpected"; then
    echo "  $(red FAIL) $label  (should NOT contain '$unexpected')"
    FAIL=$((FAIL + 1))
  else
    echo "  $(green PASS) $label"
    PASS=$((PASS + 1))
  fi
}

# JSON-RPC call to /mcp — returns result text
mcp_call() {
  local method="$1" params="$2"
  local id
  id=$RANDOM
  curl -sf -X POST "$MCP_URL/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"$method\",\"params\":$params}" \
    2>/dev/null || echo '{"error":"connection_failed"}'
}

# ---------- pre-flight ----------
echo ""
bold "============================================"
bold " Elasticsearch + MCP Server Integration Tests"
bold "============================================"
echo ""

echo "--- Pre-flight checks ---"

# Check Elasticsearch
ES_HEALTH=$(curl -sf "$ES_URL/_cluster/health" 2>/dev/null || echo "")
if [ -z "$ES_HEALTH" ]; then
  echo "$(red 'ERROR'): Elasticsearch not reachable at $ES_URL"
  echo "Run: docker compose -f compose.test.yml up --build -d"
  exit 1
fi
echo "  Elasticsearch: $(echo "$ES_HEALTH" | grep -o '"status":"[^"]*"')"

# Check alert count
ALERT_COUNT=$(curl -sf "$ES_URL/wazuh-alerts-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")
echo "  Mock alerts:   $ALERT_COUNT"

# Check vuln count
VULN_COUNT=$(curl -sf "$ES_URL/wazuh-states-vulnerabilities-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*' || echo "0")
echo "  Mock vulns:    $VULN_COUNT"

# Check MCP server (may return 503 if Wazuh Manager is unreachable — that's OK for ES tests)
MCP_HEALTH=$(curl -s "$MCP_URL/health" 2>/dev/null || echo "")
if [ -z "$MCP_HEALTH" ]; then
  echo "$(red 'ERROR'): MCP server not reachable at $MCP_URL"
  exit 1
fi
echo "  MCP server:    reachable"
echo ""

# ==========================================================================
echo "$(bold '=== 1. Health & Elasticsearch connectivity ===')"

assert_contains "health endpoint returns status" "$MCP_HEALTH" '"status"'
assert_contains "elasticsearch service reported" "$MCP_HEALTH" '"elasticsearch"'
# Wazuh Manager is unreachable in this test, so overall status is "degraded" — that's expected
# We only care that Elasticsearch is reported and configured
assert_contains "elasticsearch tools available" "$MCP_HEALTH" '"available":true'
echo ""

# ==========================================================================
echo "$(bold '=== 2. MCP Initialize ===')"

INIT=$(mcp_call "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}')
assert_contains "initialize returns serverInfo" "$INIT" '"serverInfo"'
assert_contains "initialize returns protocolVersion" "$INIT" '"protocolVersion"'
echo ""

# ==========================================================================
echo "$(bold '=== 3. tools/list ===')"

TOOLS=$(mcp_call "tools/list" '{}')
assert_contains "tools/list returns get_wazuh_alerts" "$TOOLS" 'get_wazuh_alerts'
assert_contains "tools/list returns get_wazuh_vulnerabilities" "$TOOLS" 'get_wazuh_vulnerabilities'
assert_contains "tools/list returns get_wazuh_vulnerability_summary" "$TOOLS" 'get_wazuh_vulnerability_summary'
assert_contains "tools/list returns get_wazuh_critical_vulnerabilities" "$TOOLS" 'get_wazuh_critical_vulnerabilities'
echo ""

# ==========================================================================
echo "$(bold '=== 4. get_wazuh_alerts (all) ===')"

ALERTS=$(mcp_call "tools/call" '{"name":"get_wazuh_alerts","arguments":{"limit":50}}')
assert_contains "alerts returns content" "$ALERTS" '"content"'
assert_contains "alerts contain affected_items" "$ALERTS" 'affected_items'
assert_contains "alerts contain brute force alert" "$ALERTS" 'brute force'
assert_contains "alerts contain SQL injection" "$ALERTS" 'SQL injection'
assert_contains "alerts contain rootkit" "$ALERTS" 'rootkit'
echo ""

# ==========================================================================
echo "$(bold '=== 5. get_wazuh_alerts (filtered by agent_id) ===')"

ALERTS_AGENT=$(mcp_call "tools/call" '{"name":"get_wazuh_alerts","arguments":{"agent_id":"001","limit":50}}')
assert_contains "agent 001 alerts return content" "$ALERTS_AGENT" '"content"'
assert_contains "agent 001 alerts contain SSH" "$ALERTS_AGENT" 'sshd'
assert_not_contains "agent 001 does NOT contain agent 002 rootkit" "$ALERTS_AGENT" 'Possible rootkit'
echo ""

# ==========================================================================
echo "$(bold '=== 6. get_wazuh_alerts (filtered by level) ===')"

ALERTS_LEVEL=$(mcp_call "tools/call" '{"name":"get_wazuh_alerts","arguments":{"level":"12","limit":50}}')
assert_contains "level>=12 returns content" "$ALERTS_LEVEL" '"content"'
assert_contains "level>=12 includes brute force (14)" "$ALERTS_LEVEL" 'brute force'
assert_contains "level>=12 includes rootkit (15)" "$ALERTS_LEVEL" 'rootkit'
assert_contains "level>=12 includes suspicious process (12)" "$ALERTS_LEVEL" 'Suspicious process'
assert_not_contains "level>=12 excludes SQL injection (6)" "$ALERTS_LEVEL" 'SQL injection'
echo ""

# ==========================================================================
echo "$(bold '=== 7. get_wazuh_alerts (filtered by rule_id) ===')"

ALERTS_RULE=$(mcp_call "tools/call" '{"name":"get_wazuh_alerts","arguments":{"rule_id":"5710","limit":50}}')
assert_contains "rule 5710 returns content" "$ALERTS_RULE" '"content"'
assert_contains "rule 5710 contains SSH failed login" "$ALERTS_RULE" 'non-existent user'
echo ""

# ==========================================================================
echo "$(bold '=== 8. get_wazuh_vulnerabilities (all) ===')"

VULNS=$(mcp_call "tools/call" '{"name":"get_wazuh_vulnerabilities","arguments":{"limit":50,"compact":false}}')
assert_contains "vulns returns content" "$VULNS" '"content"'
assert_contains "vulns contain CVE-2024-3094" "$VULNS" 'CVE-2024-3094'
assert_contains "vulns contain CVE-2024-21626" "$VULNS" 'CVE-2024-21626'
assert_contains "vulns contain xz-utils package" "$VULNS" 'xz-utils'
echo ""

# ==========================================================================
echo "$(bold '=== 9. get_wazuh_vulnerabilities (filtered by severity) ===')"

VULNS_CRIT=$(mcp_call "tools/call" '{"name":"get_wazuh_vulnerabilities","arguments":{"severity":"critical","limit":50,"compact":false}}')
assert_contains "critical vulns returns content" "$VULNS_CRIT" '"content"'
assert_contains "critical vulns contain CVE-2024-3094" "$VULNS_CRIT" 'CVE-2024-3094'
assert_contains "critical vulns contain CVE-2024-21626" "$VULNS_CRIT" 'CVE-2024-21626'
assert_not_contains "critical vulns exclude Medium CVE" "$VULNS_CRIT" 'CVE-2023-32233'
echo ""

# ==========================================================================
echo "$(bold '=== 10. get_wazuh_critical_vulnerabilities ===')"

CRIT_VULNS=$(mcp_call "tools/call" '{"name":"get_wazuh_critical_vulnerabilities","arguments":{"limit":50,"compact":false}}')
assert_contains "critical vulns tool returns content" "$CRIT_VULNS" '"content"'
assert_contains "critical vulns tool contains XZ backdoor" "$CRIT_VULNS" 'CVE-2024-3094'
echo ""

# ==========================================================================
echo "$(bold '=== 11. get_wazuh_vulnerability_summary ===')"

VULN_SUMMARY=$(mcp_call "tools/call" '{"name":"get_wazuh_vulnerability_summary","arguments":{}}')
assert_contains "vuln summary returns content" "$VULN_SUMMARY" '"content"'
assert_contains "vuln summary has Critical count" "$VULN_SUMMARY" 'Critical'
assert_contains "vuln summary has High count" "$VULN_SUMMARY" 'High'
echo ""

# ==========================================================================
echo "$(bold '=== 12. get_wazuh_alerts with timestamp range (search equivalent) ===')"

# Use explicit timestamp range to match our mock data (Jan 2024)
SEARCH=$(mcp_call "tools/call" '{"name":"get_wazuh_alerts","arguments":{"timestamp_start":"2024-01-01T00:00:00.000Z","timestamp_end":"2024-02-01T00:00:00.000Z","limit":50}}')
assert_contains "timestamp-filtered alerts returns content" "$SEARCH" '"content"'
assert_contains "timestamp-filtered alerts find brute force" "$SEARCH" 'brute force'
assert_contains "timestamp-filtered alerts find rootkit" "$SEARCH" 'rootkit'
echo ""

# ==========================================================================
echo "$(bold '=== 13. analyze_security_threat (no time filter — queries all alerts) ===')"

# Uses get_alerts(limit=100) with NO time filter, then searches for indicator text
# Our mock data has srcip "10.0.0.99" in SSH brute force alerts
THREAT=$(mcp_call "tools/call" '{"name":"analyze_security_threat","arguments":{"indicator":"10.0.0.99","indicator_type":"ip"}}')
assert_contains "threat analysis returns content" "$THREAT" '"content"'
assert_contains "threat analysis finds matching alerts" "$THREAT" 'matching_alerts'
assert_contains "threat analysis finds the IP in alerts" "$THREAT" '10.0.0.99'
echo ""

# ==========================================================================
echo "$(bold '=== 14. check_ioc_reputation (no time filter — queries all alerts) ===')"

# Uses get_alerts(limit=500) with NO time filter, searches for indicator
# "10.0.0.99" appears in 3 SSH attack alerts (levels 10, 10, 14)
IOC=$(mcp_call "tools/call" '{"name":"check_ioc_reputation","arguments":{"indicator":"10.0.0.99","indicator_type":"ip"}}')
assert_contains "IoC check returns content" "$IOC" '"content"'
assert_contains "IoC check has occurrences field" "$IOC" 'occurrences'
assert_contains "IoC check has risk field" "$IOC" 'risk'
# max_alert_level should be >= 10 so risk should be "high"
assert_contains "IoC check rates IP as high risk" "$IOC" 'high'
echo ""

# ==========================================================================
echo "$(bold '=== 15. get_wazuh_alert_summary (time-range relative — empty but valid) ===')"

# Uses _time_range_to_start("24h") — our 2024 mock data is outside this window
# Should return valid response with total_alerts: 0
SUMMARY=$(mcp_call "tools/call" '{"name":"get_wazuh_alert_summary","arguments":{"time_range":"24h","group_by":"rule.level"}}')
assert_contains "alert summary returns content" "$SUMMARY" '"content"'
assert_contains "alert summary has total_alerts" "$SUMMARY" 'total_alerts'
assert_contains "alert summary has groups" "$SUMMARY" 'groups'
echo ""

# ==========================================================================
echo "$(bold '=== 16. analyze_alert_patterns (time-range relative — empty but valid) ===')"

# Uses _time_range_to_start("7d") — outside our mock data window
# Should return valid response with empty patterns
PATTERNS=$(mcp_call "tools/call" '{"name":"analyze_alert_patterns","arguments":{"time_range":"7d","min_frequency":1}}')
assert_contains "pattern analysis returns content" "$PATTERNS" '"content"'
assert_contains "pattern analysis has patterns field" "$PATTERNS" 'patterns'
assert_contains "pattern analysis has total_patterns" "$PATTERNS" 'total_patterns'
echo ""

# ==========================================================================
echo "$(bold '=== 17. search_security_events (time-range relative — empty but valid) ===')"

# Uses _time_range_to_start("7d") — outside our mock data window
# Should return valid response with empty affected_items
EVENTS=$(mcp_call "tools/call" '{"name":"search_security_events","arguments":{"query":"brute force","time_range":"7d","limit":50}}')
assert_contains "search events returns content" "$EVENTS" '"content"'
assert_contains "search events has affected_items" "$EVENTS" 'affected_items'
echo ""

# ==========================================================================
echo "$(bold '=== 18. get_top_security_threats (time-range relative — empty but valid) ===')"

# Uses _time_range_to_start("7d") — outside our mock data window
# Should return valid response with empty threats list
THREATS=$(mcp_call "tools/call" '{"name":"get_top_security_threats","arguments":{"limit":10,"time_range":"7d"}}')
assert_contains "top threats returns content" "$THREATS" '"content"'
assert_contains "top threats has threats field" "$THREATS" 'threats'
echo ""

# ##########################################################################
# WAZUH MANAGER-DEPENDENT TOOLS (require real Wazuh Manager API)
# ##########################################################################

# Pre-check: is Wazuh Manager reachable? (authenticate to verify)
MANAGER_OK="false"
MANAGER_CHECK=$(curl -sk -u "wazuh-wui:MyS3cr37P450r.*-" -X POST "https://localhost:55000/security/user/authenticate" 2>/dev/null || echo "")
if echo "$MANAGER_CHECK" | grep -q "token"; then
  MANAGER_OK="true"
  echo "$(bold '--- Wazuh Manager detected — running full Manager tool tests ---')"
  echo ""
else
  echo "$(bold '--- Wazuh Manager NOT detected — skipping Manager-only tests ---')"
  echo ""
fi

if [ "$MANAGER_OK" = "true" ]; then

# ==========================================================================
echo "$(bold '=== 19. perform_risk_assessment (Manager + ES) ===')"

RISK=$(mcp_call "tools/call" '{"name":"perform_risk_assessment","arguments":{}}')
assert_contains "risk assessment returns content" "$RISK" '"content"'
assert_contains "risk assessment has risk_level" "$RISK" 'risk_level'
assert_contains "risk assessment has total_agents" "$RISK" 'total_agents'
echo ""

# ==========================================================================
echo "$(bold '=== 20. generate_security_report (Manager + ES) ===')"

REPORT=$(mcp_call "tools/call" '{"name":"generate_security_report","arguments":{"report_type":"daily","include_recommendations":true}}')
assert_contains "report returns content" "$REPORT" '"content"'
assert_contains "report has sections" "$REPORT" 'sections'
assert_contains "report has agents section" "$REPORT" 'agents'
assert_contains "report has vulnerabilities section" "$REPORT" 'vulnerabilities'
echo ""

# ==========================================================================
echo "$(bold '=== 21. get_wazuh_agents ===')"

AGENTS=$(mcp_call "tools/call" '{"name":"get_wazuh_agents","arguments":{"limit":10}}')
assert_contains "agents returns content" "$AGENTS" '"content"'
assert_contains "agents has affected_items" "$AGENTS" 'affected_items'
echo ""

# ==========================================================================
echo "$(bold '=== 22. get_wazuh_running_agents ===')"

RUNNING=$(mcp_call "tools/call" '{"name":"get_wazuh_running_agents","arguments":{}}')
assert_contains "running agents returns content" "$RUNNING" '"content"'
assert_contains "running agents has affected_items" "$RUNNING" 'affected_items'
echo ""

# ==========================================================================
echo "$(bold '=== 23. validate_wazuh_connection ===')"

VALIDATE=$(mcp_call "tools/call" '{"name":"validate_wazuh_connection","arguments":{}}')
assert_contains "validate connection returns content" "$VALIDATE" '"content"'
assert_contains "validate connection has data" "$VALIDATE" 'data'
echo ""

# ==========================================================================
echo "$(bold '=== 24. get_wazuh_rules_summary ===')"

RULES=$(mcp_call "tools/call" '{"name":"get_wazuh_rules_summary","arguments":{}}')
assert_contains "rules summary returns content" "$RULES" '"content"'
assert_contains "rules summary has data" "$RULES" 'data'
echo ""

# ==========================================================================
echo "$(bold '=== 25. get_wazuh_weekly_stats ===')"

# Note: get_wazuh_statistics needs stats files that may not exist on a fresh manager
# Using weekly_stats which is more reliably available
STATS=$(mcp_call "tools/call" '{"name":"get_wazuh_weekly_stats","arguments":{}}')
assert_contains "weekly stats returns content" "$STATS" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 26. get_wazuh_cluster_health (cluster disabled — expect error) ===')"

# Cluster is disabled in single-node test setup; verify we get a valid JSON-RPC response
CLUSTER=$(mcp_call "tools/call" '{"name":"get_wazuh_cluster_health","arguments":{}}')
assert_contains "cluster health returns jsonrpc response" "$CLUSTER" 'jsonrpc'
echo ""

# ==========================================================================
echo "$(bold '=== 27. get_wazuh_remoted_stats ===')"

REMOTED=$(mcp_call "tools/call" '{"name":"get_wazuh_remoted_stats","arguments":{}}')
assert_contains "remoted stats returns content" "$REMOTED" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 28. get_wazuh_log_collector_stats ===')"

LOGCOL=$(mcp_call "tools/call" '{"name":"get_wazuh_log_collector_stats","arguments":{}}')
assert_contains "log collector stats returns content" "$LOGCOL" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 29. search_wazuh_manager_logs ===')"

# Wazuh API q= parameter expects field=value format, not freetext
LOGS=$(mcp_call "tools/call" '{"name":"search_wazuh_manager_logs","arguments":{"query":"level=error","limit":10}}')
assert_contains "search logs returns content" "$LOGS" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 30. get_wazuh_manager_error_logs ===')"

ERRLOGS=$(mcp_call "tools/call" '{"name":"get_wazuh_manager_error_logs","arguments":{"limit":10}}')
assert_contains "error logs returns content" "$ERRLOGS" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 31. run_compliance_check ===')"

COMPLIANCE=$(mcp_call "tools/call" '{"name":"run_compliance_check","arguments":{"framework":"PCI-DSS"}}')
assert_contains "compliance check returns content" "$COMPLIANCE" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 32. get_health_status (full — Manager + ES) ===')"

HEALTH_FULL=$(curl -s "$MCP_URL/health" 2>/dev/null)
assert_contains "full health has wazuh_manager healthy" "$HEALTH_FULL" '"wazuh_manager":"healthy"'
assert_contains "full health has elasticsearch healthy" "$HEALTH_FULL" '"elasticsearch":"healthy"'
echo ""

# ==========================================================================
# Verification tools that use ES (work even without registered agents)
# ==========================================================================
echo "$(bold '=== 33. wazuh_check_blocked_ip (ES — searches alerts for firewall-drop) ===')"

# Searches alerts for IP + "firewall-drop" text. Our mock data doesn't have firewall-drop
# alerts, so blocked should be false — but it should return a valid response
BLOCKED=$(mcp_call "tools/call" '{"name":"wazuh_check_blocked_ip","arguments":{"ip_address":"10.0.0.99"}}')
assert_contains "check blocked IP returns content" "$BLOCKED" '"content"'
assert_contains "check blocked IP has ip_address" "$BLOCKED" '10.0.0.99'
assert_contains "check blocked IP has blocked field" "$BLOCKED" 'blocked'
echo ""

# ==========================================================================
echo "$(bold '=== 34. wazuh_check_user_status (ES — searches alerts for disable/enable-account) ===')"

# Searches alerts for username + agent_id + disable/enable-account text
# Agent 001 exists in mock data but no disable-account alerts
USERSTATUS=$(mcp_call "tools/call" '{"name":"wazuh_check_user_status","arguments":{"agent_id":"001","username":"admin"}}')
assert_contains "check user status returns content" "$USERSTATUS" '"content"'
assert_contains "check user status has likely_disabled" "$USERSTATUS" 'likely_disabled'
echo ""

# ==========================================================================
# Agent-specific Manager tools (need agent 000 which is the manager itself)
# ==========================================================================
echo "$(bold '=== 35. check_agent_health (Manager — agent 000 = manager) ===')"

AHEALTH=$(mcp_call "tools/call" '{"name":"check_agent_health","arguments":{"agent_id":"000"}}')
assert_contains "agent health returns content" "$AHEALTH" '"content"'
assert_contains "agent health has status" "$AHEALTH" 'status'
echo ""

# ==========================================================================
echo "$(bold '=== 36. get_agent_processes (Manager — agent 000) ===')"

PROCS=$(mcp_call "tools/call" '{"name":"get_agent_processes","arguments":{"agent_id":"000","limit":5}}')
assert_contains "agent processes returns content" "$PROCS" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 37. get_agent_ports (Manager — agent 000) ===')"

PORTS=$(mcp_call "tools/call" '{"name":"get_agent_ports","arguments":{"agent_id":"000","limit":5}}')
assert_contains "agent ports returns content" "$PORTS" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 38. get_agent_configuration (Manager — agent 000) ===')"

ACONF=$(mcp_call "tools/call" '{"name":"get_agent_configuration","arguments":{"agent_id":"000"}}')
assert_contains "agent config returns content" "$ACONF" '"content"'
echo ""

# ==========================================================================
echo "$(bold '=== 39. get_wazuh_cluster_nodes ===')"

# Cluster is disabled in single-node, expect valid jsonrpc response (error or data)
NODES=$(mcp_call "tools/call" '{"name":"get_wazuh_cluster_nodes","arguments":{}}')
assert_contains "cluster nodes returns jsonrpc response" "$NODES" 'jsonrpc'
echo ""

# ==========================================================================
echo "$(bold '=== 40. get_wazuh_statistics ===')"

# May fail on fresh Manager (stats file not yet generated) — that's OK
WSTATS=$(mcp_call "tools/call" '{"name":"get_wazuh_statistics","arguments":{}}')
assert_contains "statistics returns jsonrpc response" "$WSTATS" 'jsonrpc'
echo ""

# ==========================================================================
echo "$(bold '=== 41. wazuh_check_agent_isolation (Manager + ES) ===')"

# Checks agent 000 status (manager) + ES alert history for host-isolation
ISOLATION=$(mcp_call "tools/call" '{"name":"wazuh_check_agent_isolation","arguments":{"agent_id":"000"}}')
assert_contains "isolation check returns content" "$ISOLATION" '"content"'
assert_contains "isolation check has isolated field" "$ISOLATION" 'isolated'
echo ""

# ==========================================================================
echo "$(bold '=== 42. wazuh_check_file_quarantine (Manager — syscheck) ===')"

# Agent 000 (manager) doesn't support syscheck queries — expect valid jsonrpc response
QUARANTINE=$(mcp_call "tools/call" '{"name":"wazuh_check_file_quarantine","arguments":{"agent_id":"000","file_path":"/etc/passwd"}}')
assert_contains "quarantine check returns jsonrpc response" "$QUARANTINE" 'jsonrpc'
echo ""

# ==========================================================================
echo "$(bold '=== 43. wazuh_check_process (Manager — syscollector) ===')"

PCHECK=$(mcp_call "tools/call" '{"name":"wazuh_check_process","arguments":{"agent_id":"000","process_id":1}}')
assert_contains "process check returns content" "$PCHECK" '"content"'
assert_contains "process check has running field" "$PCHECK" 'running'
echo ""

else
  # Manager not available — just test the ES-only verification tools
  echo "$(bold '=== 19-32. Manager tools (skipped — no Wazuh Manager) ===')"
  echo "  SKIP  Manager-dependent tools not tested"
  echo ""

  # These verification tools only need ES, no Manager
  echo "$(bold '=== 33. wazuh_check_blocked_ip (ES-only) ===')"
  BLOCKED=$(mcp_call "tools/call" '{"name":"wazuh_check_blocked_ip","arguments":{"ip_address":"10.0.0.99"}}')
  assert_contains "check blocked IP returns content" "$BLOCKED" '"content"'
  assert_contains "check blocked IP has blocked field" "$BLOCKED" 'blocked'
  echo ""

  echo "$(bold '=== 34. wazuh_check_user_status (ES-only) ===')"
  USERSTATUS=$(mcp_call "tools/call" '{"name":"wazuh_check_user_status","arguments":{"agent_id":"001","username":"admin"}}')
  assert_contains "check user status returns content" "$USERSTATUS" '"content"'
  assert_contains "check user status has likely_disabled" "$USERSTATUS" 'likely_disabled'
  echo ""
fi

# ==========================================================================
echo ""
bold "============================================"
bold " Results: $PASS passed, $FAIL failed, $TOTAL total"
bold "============================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
