# DFIR Skills Index

Curated pointer into the `cybersecurity-skills` plugin. Grouped by IR phase and topic. Each entry is a skill name — invoke by asking Claude about the topic (e.g., *"walk me through analyzing Windows Amcache"*) and the plugin will load the matching `SKILL.md` on demand.

---

## 1. Evidence Acquisition
- `acquiring-disk-image-with-dd-and-dcfldd`
- `collecting-volatile-evidence-from-compromised-host`
- `performing-cloud-storage-forensic-acquisition`
- `performing-mobile-device-forensics-with-cellebrite`

## 2. Triage & Initial Response
- `triaging-security-incident`
- `triaging-security-incident-with-ir-playbook`
- `performing-alert-triage-with-elastic-siem`
- `performing-endpoint-forensics-investigation`
- `performing-web-application-vulnerability-triage`
- `performing-malware-triage-with-yara`

## 3. Memory Forensics
- `analyzing-memory-dumps-with-volatility`
- `conducting-memory-forensics-with-volatility`
- `performing-memory-forensics-with-volatility3`
- `performing-memory-forensics-with-volatility3-plugins`
- `analyzing-memory-forensics-with-lime-and-volatility`
- `extracting-memory-artifacts-with-rekall`
- `extracting-credentials-from-memory-dump`

## 4. Disk & Filesystem Forensics
- `analyzing-disk-image-with-autopsy`
- `performing-disk-forensics-investigation`
- `analyzing-slack-space-and-file-system-artifacts`
- `performing-sqlite-database-forensics`

## 5. Windows Artifacts
- `analyzing-windows-registry-for-artifacts`
- `analyzing-windows-amcache-artifacts`
- `analyzing-windows-lnk-files-for-artifacts`
- `analyzing-windows-shellbag-artifacts`
- `analyzing-lnk-file-and-jump-list-artifacts`
- `extracting-windows-event-logs-artifacts`
- `performing-windows-artifact-analysis-with-eric-zimmerman-tools`
- `hunting-for-registry-persistence-mechanisms`
- `hunting-for-registry-run-key-persistence`

## 6. Linux / macOS Artifacts
- `analyzing-linux-system-artifacts`
- `performing-linux-log-forensics-investigation`
- `analyzing-docker-container-forensics`

## 7. Browser & Email Forensics
- `analyzing-browser-forensics-with-hindsight`
- `extracting-browser-history-artifacts`
- `analyzing-outlook-pst-for-email-forensics`
- `investigating-phishing-email-incident`

## 8. Network Forensics
- `performing-network-forensics-with-wireshark`
- `analyzing-network-traffic-for-incidents`
- `analyzing-network-traffic-of-malware`
- `analyzing-network-covert-channels-in-malware`

## 9. Timeline & Log Analysis
- `building-incident-timeline-with-timesketch`
- `performing-timeline-reconstruction-with-plaso`
- `performing-log-analysis-for-forensic-investigation`

## 10. Malware Analysis (Static / Dynamic / RE)
- `performing-static-malware-analysis-with-pe-studio`
- `analyzing-malware-behavior-with-cuckoo-sandbox`
- `performing-automated-malware-analysis-with-cape`
- `analyzing-malware-sandbox-evasion-techniques`
- `analyzing-packed-malware-with-upx-unpacker`
- `analyzing-pdf-malware-with-pdfid`
- `analyzing-macro-malware-in-office-documents`
- `reverse-engineering-malware-with-ghidra`
- `reverse-engineering-dotnet-malware-with-dnspy`
- `reverse-engineering-rust-malware`
- `reverse-engineering-android-malware-with-jadx`
- `analyzing-android-malware-with-apktool`
- `analyzing-linux-elf-malware`
- `analyzing-golang-malware-with-ghidra`
- `deobfuscating-javascript-malware`
- `deobfuscating-powershell-obfuscated-malware`
- `detecting-fileless-malware-techniques`
- `detecting-mobile-malware-behavior`
- `analyzing-malware-persistence-with-autoruns`
- `performing-firmware-malware-analysis`
- `performing-malware-persistence-investigation`
- `analyzing-powershell-empire-artifacts`
- `analyzing-supply-chain-malware-artifacts`
- `analyzing-malware-family-relationships-with-malpedia`

## 11. IOC Handling
- `extracting-iocs-from-malware-samples`
- `performing-malware-ioc-extraction`
- `automating-ioc-enrichment`
- `performing-ioc-enrichment-automation`
- `performing-malware-hash-enrichment-with-virustotal`
- `building-ioc-defanging-and-sharing-pipeline`
- `building-ioc-enrichment-pipeline-with-opencti`

## 12. Cloud Forensics & IR
- `conducting-cloud-incident-response`
- `performing-cloud-forensics-investigation`
- `performing-cloud-forensics-with-aws-cloudtrail`
- `performing-cloud-log-forensics-with-athena`
- `performing-cloud-native-forensics-with-falco`
- `performing-cloud-incident-containment-procedures`

## 13. Specialized IR Playbooks
- `conducting-malware-incident-response`
- `conducting-phishing-incident-response`
- `investigating-ransomware-attack-artifacts`
- `implementing-ot-incident-response-playbook`
- `eradicating-malware-from-infected-systems`
- `building-incident-response-playbook`

## 14. IR Operations & Reporting
- `building-incident-response-dashboard`
- `implementing-ticketing-system-for-incidents`
- `building-malware-incident-communication-template`
- `conducting-post-incident-lessons-learned`
- `analyzing-campaign-attribution-evidence`
- `building-automated-malware-submission-pipeline`
