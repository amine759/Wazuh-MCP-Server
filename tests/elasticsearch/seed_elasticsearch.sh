#!/bin/sh
# Seed Elasticsearch with mock Wazuh alert and vulnerability data.
# Runs inside the es-seed container after Elasticsearch is healthy.

set -e

ES_URL="http://elasticsearch:9200"

echo "=== Seeding Elasticsearch with mock Wazuh data ==="

# ---------- Wait for ES (belt-and-suspenders) ----------
for i in $(seq 1 30); do
  if curl -sf "$ES_URL/_cluster/health" > /dev/null 2>&1; then
    echo "Elasticsearch is ready."
    break
  fi
  echo "Waiting for Elasticsearch... ($i/30)"
  sleep 2
done

# ---------- Create wazuh-alerts index (idempotent) ----------
echo ""
echo "--- Creating wazuh-alerts-2024.01.15 index ---"

curl -s -X PUT "$ES_URL/wazuh-alerts-2024.01.15" -H 'Content-Type: application/json' -d '{
  "settings": { "number_of_shards": 1, "number_of_replicas": 0 }
}' || true
echo ""

# Bulk-insert alerts
echo "--- Inserting mock alerts ---"
curl -s -X POST "$ES_URL/wazuh-alerts-2024.01.15/_bulk" -H 'Content-Type: application/x-ndjson' -d '
{"index":{}}
{"timestamp":"2024-01-15T10:00:00.000Z","rule":{"id":"5710","level":10,"description":"sshd: Attempt to login using a non-existent user","groups":["syslog","sshd","authentication_failed"],"mitre":{"id":["T1110"],"tactic":["Credential Access"]}},"agent":{"id":"001","name":"web-server-01","ip":"192.168.1.10"},"data":{"srcip":"10.0.0.99","srcport":"44312","dstuser":"admin"},"location":"/var/log/auth.log"}
{"index":{}}
{"timestamp":"2024-01-15T10:05:00.000Z","rule":{"id":"5710","level":10,"description":"sshd: Attempt to login using a non-existent user","groups":["syslog","sshd","authentication_failed"],"mitre":{"id":["T1110"],"tactic":["Credential Access"]}},"agent":{"id":"001","name":"web-server-01","ip":"192.168.1.10"},"data":{"srcip":"10.0.0.99","srcport":"44315","dstuser":"root"},"location":"/var/log/auth.log"}
{"index":{}}
{"timestamp":"2024-01-15T10:10:00.000Z","rule":{"id":"5712","level":14,"description":"sshd: brute force attack detected","groups":["syslog","sshd","authentication_failed"],"mitre":{"id":["T1110.001"],"tactic":["Credential Access"]}},"agent":{"id":"001","name":"web-server-01","ip":"192.168.1.10"},"data":{"srcip":"10.0.0.99","srcport":"44320","dstuser":"root"},"location":"/var/log/auth.log"}
{"index":{}}
{"timestamp":"2024-01-15T11:00:00.000Z","rule":{"id":"100002","level":12,"description":"Suspicious process execution detected","groups":["ossec","rootcheck","malware"],"mitre":{"id":["T1059"],"tactic":["Execution"]}},"agent":{"id":"002","name":"db-server-01","ip":"192.168.1.20"},"data":{"command":"/tmp/.hidden/payload","user":"www-data"},"location":"rootcheck"}
{"index":{}}
{"timestamp":"2024-01-15T11:30:00.000Z","rule":{"id":"87900","level":8,"description":"File integrity monitoring: file modified","groups":["syscheck","fim"],"mitre":{"id":["T1565"],"tactic":["Impact"]}},"agent":{"id":"002","name":"db-server-01","ip":"192.168.1.20"},"data":{"path":"/etc/passwd","md5_before":"abc123","md5_after":"def456","uid":"0"},"location":"syscheck"}
{"index":{}}
{"timestamp":"2024-01-15T12:00:00.000Z","rule":{"id":"60103","level":6,"description":"Web application attack attempt: SQL injection","groups":["web","attack","sql_injection"],"mitre":{"id":["T1190"],"tactic":["Initial Access"]}},"agent":{"id":"003","name":"app-server-01","ip":"192.168.1.30"},"data":{"srcip":"203.0.113.50","url":"/api/users?id=1 OR 1=1","method":"GET"},"location":"/var/log/nginx/access.log"}
{"index":{}}
{"timestamp":"2024-01-15T12:15:00.000Z","rule":{"id":"60103","level":6,"description":"Web application attack attempt: SQL injection","groups":["web","attack","sql_injection"],"mitre":{"id":["T1190"],"tactic":["Initial Access"]}},"agent":{"id":"003","name":"app-server-01","ip":"192.168.1.30"},"data":{"srcip":"203.0.113.50","url":"/api/login?user=admin%27--","method":"POST"},"location":"/var/log/nginx/access.log"}
{"index":{}}
{"timestamp":"2024-01-15T13:00:00.000Z","rule":{"id":"550","level":5,"description":"User login failed","groups":["authentication_failed","pam"],"mitre":{"id":["T1078"],"tactic":["Defense Evasion","Persistence","Privilege Escalation","Initial Access"]}},"agent":{"id":"001","name":"web-server-01","ip":"192.168.1.10"},"data":{"srcip":"192.168.1.100","dstuser":"deploy"},"location":"/var/log/auth.log"}
{"index":{}}
{"timestamp":"2024-01-15T14:00:00.000Z","rule":{"id":"5501","level":3,"description":"PAM: Login session opened","groups":["pam","syslog","authentication_success"],"mitre":{"id":["T1078"],"tactic":["Initial Access"]}},"agent":{"id":"001","name":"web-server-01","ip":"192.168.1.10"},"data":{"dstuser":"deploy"},"location":"/var/log/auth.log"}
{"index":{}}
{"timestamp":"2024-01-15T15:00:00.000Z","rule":{"id":"100200","level":15,"description":"Possible rootkit detected: hidden process","groups":["ossec","rootcheck","rootkit"],"mitre":{"id":["T1014"],"tactic":["Defense Evasion"]}},"agent":{"id":"002","name":"db-server-01","ip":"192.168.1.20"},"data":{"title":"Rootkit detection","file":"/proc/.hidden"},"location":"rootcheck"}
'
echo ""

# ---------- Create wazuh-states-vulnerabilities index ----------
echo ""
echo "--- Creating wazuh-states-vulnerabilities-001 index ---"

curl -s -X PUT "$ES_URL/wazuh-states-vulnerabilities-001" -H 'Content-Type: application/json' -d '{
  "settings": { "number_of_shards": 1, "number_of_replicas": 0 }
}' || true
echo ""

# Bulk-insert vulnerabilities
echo "--- Inserting mock vulnerabilities ---"
curl -s -X POST "$ES_URL/wazuh-states-vulnerabilities-001/_bulk" -H 'Content-Type: application/x-ndjson' -d '
{"index":{}}
{"vulnerability":{"id":"CVE-2024-3094","severity":"Critical","description":"XZ Utils backdoor - malicious code in liblzma","reference":"https://nvd.nist.gov/vuln/detail/CVE-2024-3094","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2024-03-29T00:00:00.000Z","cvss":{"score":10.0}},"agent":{"id":"001","name":"web-server-01"},"package":{"name":"xz-utils","version":"5.6.0-0.2","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2024-21626","severity":"Critical","description":"runc container breakout via leaked file descriptor","reference":"https://nvd.nist.gov/vuln/detail/CVE-2024-21626","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2024-01-31T00:00:00.000Z","cvss":{"score":8.6}},"agent":{"id":"002","name":"db-server-01"},"package":{"name":"runc","version":"1.1.9","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2023-44487","severity":"High","description":"HTTP/2 Rapid Reset attack (DDoS)","reference":"https://nvd.nist.gov/vuln/detail/CVE-2023-44487","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2023-10-10T00:00:00.000Z","cvss":{"score":7.5}},"agent":{"id":"001","name":"web-server-01"},"package":{"name":"nginx","version":"1.24.0","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2023-38545","severity":"High","description":"curl SOCKS5 heap buffer overflow","reference":"https://nvd.nist.gov/vuln/detail/CVE-2023-38545","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2023-10-11T00:00:00.000Z","cvss":{"score":7.5}},"agent":{"id":"003","name":"app-server-01"},"package":{"name":"curl","version":"8.1.2","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2023-4911","severity":"High","description":"glibc ld.so buffer overflow (Looney Tunables)","reference":"https://nvd.nist.gov/vuln/detail/CVE-2023-4911","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2023-10-03T00:00:00.000Z","cvss":{"score":7.8}},"agent":{"id":"001","name":"web-server-01"},"package":{"name":"libc6","version":"2.35-0ubuntu3.4","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2023-32233","severity":"Medium","description":"Linux kernel nf_tables use-after-free","reference":"https://nvd.nist.gov/vuln/detail/CVE-2023-32233","status":"Active","detected_at":"2024-01-15T08:00:00.000Z","published_at":"2023-05-08T00:00:00.000Z","cvss":{"score":5.5}},"agent":{"id":"002","name":"db-server-01"},"package":{"name":"linux-image","version":"5.15.0-91","architecture":"amd64"}}
{"index":{}}
{"vulnerability":{"id":"CVE-2023-0286","severity":"Low","description":"OpenSSL X.400 address type confusion","reference":"https://nvd.nist.gov/vuln/detail/CVE-2023-0286","status":"Fixed","detected_at":"2024-01-10T08:00:00.000Z","published_at":"2023-02-08T00:00:00.000Z","cvss":{"score":3.1}},"agent":{"id":"003","name":"app-server-01"},"package":{"name":"libssl3","version":"3.0.2-0ubuntu1.12","architecture":"amd64"}}
'
echo ""

# ---------- Refresh indices so data is searchable ----------
echo "--- Refreshing indices ---"
curl -s -X POST "$ES_URL/_refresh"
echo ""

# ---------- Verify ----------
echo ""
echo "=== Verification ==="
ALERT_COUNT=$(curl -s "$ES_URL/wazuh-alerts-*/_count" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
VULN_COUNT=$(curl -s "$ES_URL/wazuh-states-vulnerabilities-*/_count" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
echo "Alerts indexed:         $ALERT_COUNT"
echo "Vulnerabilities indexed: $VULN_COUNT"
echo ""
echo "=== Seed complete ==="
