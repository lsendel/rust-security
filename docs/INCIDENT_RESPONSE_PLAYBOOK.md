# Security Incident Response Playbook

## 🚨 Emergency Contacts

| Role | Contact | Availability |
|------|---------|-------------|
| **Security Lead** | [Name] | 24/7 |
| **Engineering Manager** | [Name] | Business Hours |
| **DevOps Lead** | [Name] | 24/7 |
| **Legal Counsel** | [Name] | Business Hours |
| **PR/Communications** | [Name] | Business Hours |

**Security Hotline**: [Phone Number]  
**Security Email**: security@[domain].com  
**Incident Slack Channel**: #security-incidents

---

## 📊 Incident Classification

### Severity Levels

| Level | Definition | Response Time | Team Required |
|-------|------------|---------------|---------------|
| **P0 - Critical** | Active exploitation, data breach, service down | **Immediate** | Full incident response team |
| **P1 - High** | Vulnerability with POC, potential data exposure | **1 hour** | Security + Engineering leads |
| **P2 - Medium** | Security weakness, no immediate threat | **4 hours** | Security team |
| **P3 - Low** | Minor security issue, minimal impact | **24 hours** | Assigned engineer |

### Incident Types

1. **Data Breach** - Unauthorized access to sensitive data
2. **Service Compromise** - System or service takeover
3. **Supply Chain Attack** - Compromised dependency
4. **Credential Exposure** - Leaked secrets or tokens
5. **Denial of Service** - Service availability impact
6. **Insider Threat** - Malicious internal activity

---

## 🔄 Response Process

### Phase 1: Detection & Analysis (0-30 minutes)

#### Immediate Actions
```bash
# 1. Preserve evidence
docker logs [container] > incident_$(date +%Y%m%d_%H%M%S).log
kubectl get events -A > k8s_events_$(date +%Y%m%d_%H%M%S).log

# 2. Capture system state
ps aux > processes_$(date +%Y%m%d_%H%M%S).txt
netstat -an > connections_$(date +%Y%m%d_%H%M%S).txt

# 3. Check for indicators of compromise
grep -r "suspicious_pattern" /var/log/
cargo audit
```

#### Checklist
- [ ] Confirm incident is real (not false positive)
- [ ] Determine severity level (P0-P3)
- [ ] Identify affected systems
- [ ] Document initial findings
- [ ] Notify incident commander
- [ ] Start incident timeline

### Phase 2: Containment (30-60 minutes)

#### Short-term Containment
```bash
# Isolate affected systems
kubectl cordon [node]
kubectl drain [node] --ignore-daemonsets

# Revoke compromised credentials
kubectl delete secret [secret-name]
gh api -X DELETE /repos/[owner]/[repo]/keys/[key-id]

# Block malicious IPs
iptables -A INPUT -s [malicious-ip] -j DROP
```

#### Long-term Containment
- Patch vulnerable systems
- Reset all potentially compromised credentials
- Implement additional monitoring
- Deploy security updates

### Phase 3: Eradication (1-4 hours)

#### Remove Threat
```bash
# Remove malicious files
find / -name "[malicious-file]" -delete

# Clean infected containers
kubectl delete pod [infected-pod]
docker rmi [compromised-image]

# Update and patch
cargo update
cargo audit fix
```

#### Verification Steps
- [ ] All malicious artifacts removed
- [ ] Vulnerabilities patched
- [ ] Security tools updated
- [ ] Clean bill of health from scanners

### Phase 4: Recovery (2-8 hours)

#### System Restoration
```bash
# Restore from clean backup
kubectl apply -f clean-deployment.yaml

# Verify system integrity
sha256sum -c checksums.txt

# Monitor for reinfection
tail -f /var/log/auth.log
watch kubectl get events
```

#### Validation Checklist
- [ ] Services functioning normally
- [ ] No signs of persistence
- [ ] Monitoring alerts configured
- [ ] Performance metrics normal
- [ ] User access verified

### Phase 5: Post-Incident (24-48 hours)

#### Documentation Requirements
1. **Incident Report**
   - Timeline of events
   - Root cause analysis
   - Impact assessment
   - Remediation steps

2. **Lessons Learned**
   - What went well
   - What needs improvement
   - Action items
   - Process updates

---

## 📝 Incident Templates

### Initial Alert Template
```
SECURITY INCIDENT DETECTED
Time: [timestamp]
Severity: [P0/P1/P2/P3]
Type: [breach/compromise/exposure/etc]
Affected Systems: [list]
Initial Assessment: [description]
Incident Commander: [name]
Slack Thread: [link]
```

### Status Update Template
```
INCIDENT UPDATE #[number]
Time: [timestamp]
Current Phase: [detection/containment/eradication/recovery]
Actions Taken: [list]
Next Steps: [list]
ETA to Resolution: [time]
```

### Resolution Notice
```
INCIDENT RESOLVED
Incident ID: [ID]
Total Duration: [time]
Root Cause: [description]
Impact: [users/data/services affected]
Remediation: [completed actions]
Follow-up Required: [yes/no - details]
```

---

## 🛠️ Security Tools & Commands

### Investigation Tools
```bash
# Check for unauthorized access
last -a
grep "Failed password" /var/log/auth.log

# Network connections
ss -tulpn
lsof -i

# File integrity
find / -mtime -1 -type f  # Files modified in last day
rpm -Va  # Verify package integrity (RHEL/CentOS)
debsums -c  # Verify package integrity (Debian/Ubuntu)

# Container security
docker inspect [container]
kubectl describe pod [pod]
trivy image [image:tag]
```

### Containment Commands
```bash
# Network isolation
iptables -I INPUT -j DROP
iptables -I OUTPUT -j DROP

# Process termination
kill -9 [pid]
pkill -f [process-name]

# Account lockdown
passwd -l [username]
usermod -s /bin/false [username]

# Kubernetes isolation
kubectl taint nodes [node] key=value:NoSchedule
kubectl patch deployment [name] -p '{"spec":{"replicas":0}}'
```

### Evidence Collection
```bash
# Create forensic image
dd if=/dev/sda of=forensic_image.img bs=4M

# Memory dump
cat /proc/[pid]/maps > memory_maps.txt
gcore -o memory_dump [pid]

# Collect logs
tar czf logs_$(date +%Y%m%d).tar.gz /var/log/

# Kubernetes artifacts
kubectl get all -A -o yaml > k8s_state.yaml
kubectl logs [pod] --previous > pod_logs.txt
```

---

## 📋 Compliance & Reporting

### Regulatory Requirements

| Regulation | Notification Timeline | Requirements |
|------------|---------------------|--------------|
| **GDPR** | 72 hours | Notify authorities and affected users |
| **CCPA** | Without unreasonable delay | Notify California residents |
| **HIPAA** | 60 days | Notify HHS and affected individuals |
| **PCI DSS** | Immediately | Notify card brands and acquirer |

### Internal Reporting

1. **Immediate** (< 1 hour)
   - Security team
   - Engineering leadership
   - On-call personnel

2. **Short-term** (< 4 hours)
   - Executive team
   - Legal counsel
   - Customer success (if customer impact)

3. **Long-term** (< 24 hours)
   - Board of directors
   - Compliance team
   - External auditors

---

## 🔄 Continuous Improvement

### Post-Incident Actions

- [ ] Update security controls
- [ ] Revise detection rules
- [ ] Enhance monitoring
- [ ] Update documentation
- [ ] Conduct training
- [ ] Test incident response

### Metrics to Track

- **MTTD** (Mean Time to Detect)
- **MTTR** (Mean Time to Respond)
- **MTTC** (Mean Time to Contain)
- **MTTE** (Mean Time to Eradicate)
- **Incident frequency**
- **False positive rate**

### Regular Drills

- **Monthly**: Tabletop exercises
- **Quarterly**: Red team exercises
- **Annually**: Full incident simulation

---

## 📚 Appendix

### A. Communication Templates

**Customer Notification**
```
Dear Customer,

We are writing to inform you of a security incident that [may have/has] affected your account. 

What Happened: [Brief description]
When: [Date/time]
What Information Was Involved: [Data types]
What We Are Doing: [Response actions]
What You Should Do: [Customer actions]

We take security seriously and apologize for any inconvenience.

[Contact information]
```

### B. Legal Considerations

- Preserve all evidence
- Document all actions
- Consult legal before external communications
- Consider law enforcement involvement
- Maintain attorney-client privilege

### C. External Resources

- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [CISA Incident Response Playbook](https://www.cisa.gov/incident-response-playbook)

---

*Last Updated: August 2025*  
*Next Review: November 2025*  
*Owner: Security Team*