# Crypto.com Bug Bounty Scope Guide

**Status**: ✅ **Configured and Ready**

**HackerOne Program**: https://hackerone.com/crypto
**Tester**: rxla

---

## ⚠️ CRITICAL REMINDERS

### Before You Start ANY Scan

1. **Verify Scope on HackerOne**: https://hackerone.com/crypto/policy_scopes
   - Scope can change - always check before scanning
   - Some assets may be temporarily out of scope

2. **Start in Fixture Mode** (Safe Testing)
   ```bash
   # Test the workflow with fake data first
   # In UI: Leave "Enable Live Mode" UNCHECKED
   # OR via API: set "live": false
   ```

3. **Follow HackerOne Rules**
   - No DoS attacks
   - No social engineering
   - No accessing other users' data without permission
   - Report only through HackerOne platform

---

## Configured Scope (scope.yml)

### ✅ In-Scope Targets

Your `scope.yml` now includes:

**Primary Domains**:
- `https://crypto.com/*`
- `https://www.crypto.com/*`

**Subdomains**:
- `https://web.crypto.com/*`
- `https://merchant.crypto.com/*`
- `https://js.crypto.com/*`

**Specific Platforms**:
- `https://crypto.com/nft/*` (NFT marketplace)
- `https://crypto.com/exchange/*` (Exchange platform)

**Related Assets**:
- `https://nadex.com/*` (verify still in scope on HackerOne)

**Wildcard** (use cautiously):
- `https://*.crypto.com` - Covers all subdomains
- ⚠️ Verify each discovered subdomain is actually in scope

### ❌ Out-of-Scope (Denylist)

Automatically excluded:
- CDNs: `*.cloudfront.net`, `*.cloudflare.com`, `*.akamai.net`
- Third-party: `*.amazonaws.com`, `*.fastly.net`
- Analytics: `*.google-analytics.com`, `*.googletagmanager.com`
- Social: `*.facebook.com`, `*.twitter.com`, `*.linkedin.com`
- Blog/Status: `blog.crypto.com`, `status.crypto.com`
- External: `*.etherscan.io` (not owned by Crypto.com)

---

## Safety Settings

### Rate Limits
```yaml
requests_per_second: 2      # Conservative to avoid DoS flags
concurrency: 2              # Max parallel requests
max_requests_per_scan: 10000  # Budget per scan
```

### Allowed Methods
Currently enabled (safe methods only):
- `GET` ✅
- `HEAD` ✅
- `OPTIONS` ✅

To enable POST/PUT/DELETE for testing forms/APIs:
- Edit `scope.yml` lines 102-106 (uncomment)
- **Only enable if HackerOne program allows**

### Tool Settings

**Zypheron** (Asset Discovery):
- `aggressive_mode: false` - Passive only
- `subdomain_bruteforce: false` - No brute force
- `port_scan_range: "common"` - Standard ports only

**VibePentester** (Penetration Testing):
- `aggressive_mode: false`
- `enable_sqlmap: false` - ⚠️ Enable only if allowed
- `enable_fuzzing: false` - ⚠️ Enable only if allowed

**Strix** (Web Scanner):
- `crawl_depth: 3` - Limited depth
- `follow_redirects: true`
- `check_robots_txt: true` - Respects robots.txt

---

## How to Use

### Option 1: Via UI (Recommended)

1. **Start Chimera UI** (should auto-launch):
   ```bash
   # If not running:
   docker-compose up -d
   ```

2. **Navigate to Runs Tab**

3. **Select Pipeline**:
   - **Task Runner**: For direct API/web testing (Autoswagger → Strix → Shannon)
   - **Recon Pipeline**: For intelligence gathering (Zypheron → Vibe → Decepticon)

4. **Load Scope**:
   - Click "Load Scope from File"
   - OR paste scope.yml content into text box

5. **Configure Mode**:
   - **Fixture Mode** (default): Safe, no real requests
   - **Live Mode**: Real testing (check "Enable Live Mode" + confirm)

6. **Start Scan**:
   - Click "Run"
   - Monitor progress in Console tab
   - View findings in Findings tab

### Option 2: Via API

```bash
# Submit a run (Task Runner)
curl -X POST http://localhost:8000/v1/run \
  -H "Content-Type: application/json" \
  -d '{
    "scope_text": "'"$(cat scope.yml)"'",
    "live": false,
    "program_name": "Crypto.com Bug Bounty"
  }'

# Submit a recon run (Recon Pipeline)
curl -X POST http://localhost:8000/v1/recon/run \
  -H "Content-Type: application/json" \
  -d '{
    "scope_text": "'"$(cat scope.yml)"'",
    "live": false,
    "live_confirm": "",
    "rate_limit_rps": 2,
    "timeout_s": 1800,
    "program_name": "Crypto.com Bug Bounty"
  }'
```

### Option 3: Via Integration Test

```bash
# Test the recon pipeline end-to-end
python test_recon_integration.py

# Expected output:
# ✓ Config loaded
# ✓ API healthy
# ✓ Run created
# ✓ Run completed
# ✓ Bundles found
```

---

## Workflow Recommendations

### Phase 1: Reconnaissance (Safe, Passive)

**Pipeline**: Recon Pipeline
**Mode**: Fixture first, then Live (passive only)

1. **Asset Discovery** (Zypheron):
   - Discover all subdomains under `*.crypto.com`
   - Identify services and ports
   - Map attack surface

2. **Verification**:
   - Cross-reference discovered assets with HackerOne scope
   - Remove any out-of-scope findings
   - Document new assets for reporting

### Phase 2: Vulnerability Testing

**Pipeline**: Task Runner
**Mode**: Live (with authorization)

1. **API Discovery** (Autoswagger):
   - Generate OpenAPI specs from endpoints
   - Identify API parameters and methods

2. **Web Scanning** (Strix):
   - Test for common vulnerabilities
   - Check authentication/authorization
   - Test input validation

3. **AI Verification** (Shannon):
   - Reduce false positives
   - Verify exploitability
   - Prioritize findings

### Phase 3: Deep Analysis

**Pipeline**: Recon Pipeline
**Mode**: Live (with authorization)

1. **Penetration Testing** (VibePentester):
   - Test high-priority targets
   - Verify vulnerabilities manually
   - Chain exploits

2. **AI Enrichment** (Decepticon):
   - Correlate findings
   - Build attack chains
   - Generate exploitation paths
   - Create report-ready documentation

### Phase 4: Reporting

1. **Export Findings**:
   - Use UI Artifacts tab
   - Download reports as JSON/Markdown
   - Include proof-of-concept

2. **Submit to HackerOne**:
   - One finding per report
   - Clear reproduction steps
   - Include screenshots/videos
   - Non-destructive PoC only

---

## Current Targets Summary

| Target | Type | Priority | Notes |
|--------|------|----------|-------|
| `crypto.com` | Main site | **HIGH** | Core platform |
| `web.crypto.com` | Web app | **HIGH** | User-facing app |
| `merchant.crypto.com` | Merchant portal | **HIGH** | Business interface |
| `js.crypto.com` | JavaScript/API | **MEDIUM** | Client-side code |
| `crypto.com/nft` | NFT marketplace | **MEDIUM** | Digital assets |
| `crypto.com/exchange` | Trading platform | **HIGH** | Financial transactions |
| `nadex.com` | Related platform | **MEDIUM** | Verify scope |
| `*.crypto.com` | Wildcard | **LOW** | Verify each subdomain |

---

## Expected Findings Types

Based on target types, likely vulnerabilities:

### Web Applications
- ✅ XSS (Reflected, Stored, DOM-based)
- ✅ CSRF
- ✅ Open Redirects
- ✅ CORS Misconfigurations
- ✅ Authentication/Authorization flaws
- ✅ Session management issues

### APIs
- ✅ API key exposure
- ✅ Parameter tampering
- ✅ Rate limiting bypass
- ✅ Mass assignment
- ✅ IDOR (Insecure Direct Object Reference)
- ✅ GraphQL injection

### Financial/Crypto Specific
- ✅ Transaction manipulation
- ✅ Wallet vulnerabilities
- ✅ Double-spend issues
- ✅ Price oracle manipulation
- ⚠️ Smart contract issues (if in scope)

### Infrastructure
- ✅ Subdomain takeover
- ✅ S3 bucket misconfig
- ✅ Information disclosure
- ✅ Version disclosure
- ✅ Directory traversal

---

## Troubleshooting

### Issue: "Reports still show example.com"

**Cause**: Running in **fixture mode** (safe, fake data)

**Fix**:
1. Check your run mode in UI or API
2. Enable Live Mode if you want real scanning
3. Confirm authorization: Type "I UNDERSTAND" in UI

### Issue: "No findings generated"

**Possible causes**:
- Fixture mode (expected - no real scanning)
- Tools not installed (zypheron/vibe/decepticon need deps)
- Rate limiting too aggressive
- Targets are well-secured (good news!)

**Debug**:
```bash
# Check run events
curl http://localhost:8000/v1/runs/{run_id}/events

# Check artifacts
ls -la kali_data/artifacts/{run_id}/

# Check tool logs
docker-compose logs chimera-core | grep -i error
```

### Issue: "Target out of scope error"

**Cause**: Target not in allowlist or in denylist

**Fix**:
1. Verify target is in `scope.yml` allowlist
2. Check it's not in denylist
3. Update scope.yml if needed
4. Restart containers: `docker-compose restart chimera-core`

---

## Next Steps

1. ✅ **Read HackerOne Policy**: https://hackerone.com/crypto
   - Understand what's allowed
   - Check for special rules
   - Note any forbidden tests

2. ✅ **Test in Fixture Mode**:
   ```bash
   # UI: Run with "Enable Live Mode" unchecked
   # API: Set "live": false
   ```

3. ✅ **Verify Tools Work**:
   ```bash
   python test_recon_integration.py
   ```

4. ✅ **Start with Passive Recon**:
   - Use Recon Pipeline
   - Asset discovery only
   - No active testing yet

5. ✅ **Graduate to Active Testing**:
   - Enable Live Mode
   - Start with low-risk tests
   - Monitor for rate limiting

6. ✅ **Report Findings**:
   - Through HackerOne only
   - Follow disclosure policy
   - Include all required info

---

## Security & Legal

⚠️ **IMPORTANT DISCLAIMERS**

1. **Authorization**: You must have explicit permission to test these targets
2. **HackerOne Rules**: Follow all program rules and safe harbor guidelines
3. **Disclosure**: Report only through HackerOne, no public disclosure
4. **Liability**: You are responsible for your actions
5. **Compliance**: Follow all applicable laws and regulations

**If in doubt, ask the program team on HackerOne first!**

---

**Document Version**: 1.0
**Last Updated**: 2026-01-04
**Scope File**: `scope.yml`
**HackerOne User**: rxla
**System Status**: ✅ Ready for Testing
