# SDL Multi-Agent Security Squad

## Overview

The **SDL Multi-Agent Security Squad** transforms the code review agent into a comprehensive Security Development Lifecycle (SDL) enforcement system aligned with industry security best practices.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   CODE REVIEW ORCHESTRATOR                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Traditional Multi-Pass LLM Review                   │   │
│  │  • Security  • Logic  • Performance  • Compliance    │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ↓                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │       SDL Multi-Agent Security Squad                │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │   │
│  │  │   SAST   │  │   DAST   │  │   SCA    │         │   │
│  │  │  Agent   │  │  Agent   │  │  Agent   │         │   │
│  │  └──────────┘  └──────────┘  └──────────┘         │   │
│  │         ↓            ↓            ↓                 │   │
│  │  ┌───────────────────────────────────────────┐     │   │
│  │  │      SDL Champion Agent                   │     │   │
│  │  │  • STRIDE/DREAD Scoring                   │     │   │
│  │  │  • Phase Gate Enforcement (A1-A5)         │     │   │
│  │  │  • Security Champion Checklist            │     │   │
│  │  └───────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Agents

### 1. SAST Agent (Static Application Security Testing)
**Role:** Static code analysis with STRIDE threat modeling

**Tools:**
- **Semgrep**: Pattern-based SAST scanning
- **Bandit**: Python security linter

**Capabilities:**
- Detects hardcoded credentials, SQL injection, command injection
- Maps vulnerabilities to STRIDE categories
- Provides CWE/OWASP mappings

**STRIDE Mapping:**
| Vulnerability Type | STRIDE Category |
|-------------------|-----------------|
| Hardcoded credentials | Spoofing |
| SQL/Command injection | Tampering |
| Missing audit logs | Repudiation |
| Data leaks | Information Disclosure |
| Resource exhaustion | Denial of Service |
| Privilege escalation | Elevation of Privilege |

### 2. DAST Agent (Dynamic Application Security Testing)
**Role:** Runtime security testing simulation

**Tools:**
- Fuzzing simulation
- OWASP ZAP integration patterns

**Capabilities:**
- Input validation testing
- CORS misconfiguration detection
- Rate limiting verification
- Authentication/authorization testing

### 3. SCA Agent (Software Composition Analysis)
**Role:** Dependency vulnerability scanning

**Tools:**
- **Safety**: Python package vulnerability database
- **NVD API**: National Vulnerability Database lookup

**Capabilities:**
- Identifies vulnerable dependencies
- CVE lookups for installed packages
- License compliance checking
- Recommends safe versions

### 4. SDL Champion Agent
**Role:** SDL phase orchestration and DREAD scoring

**Responsibilities:**
- Aggregate findings from SAST/DAST/SCA agents
- Calculate DREAD risk scores
- Enforce SDL phase gate requirements
- Generate Security Champion checklists

## STRIDE Threat Modeling

### Categories

1. **Spoofing**: Identity verification bypass (e.g., hardcoded credentials)
2. **Tampering**: Data integrity violations (e.g., SQL injection)
3. **Repudiation**: Lack of audit trails (e.g., missing logs)
4. **Information Disclosure**: Data leaks (e.g., exposed secrets)
5. **Denial of Service**: Resource exhaustion (e.g., no rate limiting)
6. **Elevation of Privilege**: Unauthorized access (e.g., missing auth checks)

## DREAD Risk Scoring

Each vulnerability receives a **DREAD score** (1-10 per dimension):

| Dimension | Description | Example |
|-----------|-------------|---------|
| **Damage** | Severity of impact | 9/10 for SQL injection (full DB access) |
| **Reproducibility** | Ease of reproduction | 8/10 for eval() (always exploitable) |
| **Exploitability** | Effort to exploit | 7/10 for SQL injection (requires SQL knowledge) |
| **Affected Users** | Number impacted | 9/10 for auth bypass (all users) |
| **Discoverability** | Ease of discovery | 8/10 for hardcoded secrets (grep search) |

**Total Score:** 5-50 (sum of all dimensions)  
**Risk Level:**
- **CRITICAL**: 40-50 (avg 8.0-10.0)
- **HIGH**: 30-39 (avg 6.0-7.9)
- **MEDIUM**: 20-29 (avg 4.0-5.9)
- **LOW**: 5-19 (avg 1.0-3.9)

## SDL Phases (A1-A5)

### A1: Security Assessment
**Focus:** Requirements and threat identification

**Phase Gate Checklist:**
- ✅ Security requirements defined
- ✅ Privacy impact assessment complete
- ⏳ Regulatory compliance mapped

**Security Champion Duties:**
- **Architect**: Define security requirements, conduct PIA
- **Champion**: Identify sensitive data handling
- **Evangelist**: Train team on secure development

### A2: Threat Modeling
**Focus:** STRIDE analysis and attack surface mapping

**Phase Gate Checklist:**
- ✅ STRIDE analysis complete
- ✅ Attack surface documented
- ⏳ DREAD scores assigned

**Security Champion Duties:**
- **Architect**: Facilitate STRIDE sessions, assign DREAD scores
- **Champion**: Identify trust boundaries
- **Evangelist**: Share threat models with team

### A3: Secure Coding
**Focus:** Implementation with security controls

**Phase Gate Checklist:**
- ✅ SAST scans pass (zero critical)
- ✅ SCA dependency check pass
- ✅ Security-focused code review complete

**Security Champion Duties:**
- **Architect**: Review architecture for anti-patterns
- **Champion**: Run SAST/SCA in CI/CD
- **Evangelist**: Share secure coding examples

### A4: Security Testing
**Focus:** Verification and penetration testing

**Phase Gate Checklist:**
- ✅ DAST scans pass (zero high)
- ✅ Penetration test complete
- ⏳ Fuzz testing complete

**Security Champion Duties:**
- **Architect**: Coordinate external pentesting
- **Champion**: Run DAST/fuzzing
- **Evangelist**: Document testing procedures

### A5: Security Release
**Focus:** Production deployment with monitoring

**Phase Gate Checklist:**
- ✅ Security sign-off obtained
- ✅ Incident response plan documented
- ⏳ Security runbook published

**Security Champion Duties:**
- **Architect**: Provide security sign-off
- **Champion**: Verify secrets management
- **Evangelist**: Publish security release notes

## BSIMM Maturity Integration

**Building Security In Maturity Model (BSIMM)** activities tracked:

### Governance
- **SM1.1**: Publish security process
- **SM2.1**: Create security portal

### Intelligence
- **AM1.1**: Perform security research
- **AM2.1**: Create technology standards

### SSDL (Secure Software Development Lifecycle)
- **CP1.1**: Perform code review
- **CP2.1**: Use SAST tools
- **ST1.1**: Perform security testing

### Deployment
- **SE1.1**: Deploy security monitors
- **SE2.1**: Ensure host security

## Usage

### Enable SDL Mode

```bash
# Standard review
code-review review file.py

# SDL Multi-Agent Security Squad mode
code-review review --sdl-mode file.py
```

### Output Example

```markdown
# SDL Multi-Agent Security Squad Analysis

## SDL Phase Status

**Current Phase:** A3: Secure Coding
**Recommendation:** DO_NOT_MERGE - Critical threats must be resolved before A4 Testing

### Phase Gate Checklist

✅ **SAST scans pass (zero critical)** [BLOCKER]
   - Responsible: Security Champion

⏳ **SCA dependency check pass** [BLOCKER]
   - Responsible: Security Champion

### Security Champion Checklist

#### Architect
- [ ] Review architecture for security anti-patterns
- [ ] Approve cryptographic algorithm choices

#### Champion
- [ ] Run SAST scans (Semgrep, Bandit) in CI/CD
- [ ] Perform security-focused code reviews

## STRIDE/DREAD Threat Analysis

### Tampering

**SQL injection vulnerability**
- DREAD Score: 41/50 (Risk: CRITICAL)
  - Damage: 9/10
  - Reproducibility: 8/10
  - Exploitability: 7/10
  - Affected Users: 9/10
  - Discoverability: 8/10
- Mitigation: Use parameterized queries
- CWE: CWE-89
- OWASP: A03:2021 - Injection

### Spoofing

**Hardcoded API credentials**
- DREAD Score: 38/50 (Risk: HIGH)
  - Damage: 8/10
  - Reproducibility: 9/10
  - Exploitability: 6/10
  - Affected Users: 7/10
  - Discoverability: 8/10
- Mitigation: Use environment variables or secrets manager
- CWE: CWE-798

## Multi-Agent Findings Summary

- **SAST Findings:** 4
- **DAST Findings:** 2
- **SCA Findings:** 1
- **Total Threats:** 7
```

## Benefits

| Traditional SAST | SDL Multi-Agent Squad |
|------------------|----------------------|
| Pattern matching only | Context-aware threat modeling |
| No risk prioritization | DREAD risk scoring |
| No lifecycle tracking | SDL phase gates |
| No role accountability | Security Champion checklists |
| Static findings | Multi-agent validation (SAST+DAST+SCA) |

## Configuration

Enable/disable in `config.yaml`:

```yaml
security_squad:
  enabled: true
  agents:
    - sast
    - dast
    - sca
    - sdl_champion
  stride_mapping: auto
  dread_scoring: auto
```

Or via CLI flag: `--sdl-mode`

---

**Next Steps:**
1. Run SDL analysis on your codebase
2. Review STRIDE threats and DREAD scores
3. Complete Security Champion checklists
4. Progress through SDL phase gates (A1→A5)
5. Track BSIMM maturity improvements

For support, see [docs/SDL_TROUBLESHOOTING.md](SDL_TROUBLESHOOTING.md)
