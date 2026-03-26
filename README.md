# VeilHunter SIGMA Rules

SIGMA detection rules for all techniques covered by the VeilHunter hunting library.
Each rule is mapped to the corresponding VeilHunter script and MITRE ATT&CK technique.

## Rule Count

| Category | Rules |
|----------|-------|
| Persistence | 12 |
| Credential Access | 8 |
| Lateral Movement | 7 |
| Defense Evasion | 9 |
| C2 + Exfiltration | 7 |
| Impact (Pre-Ransomware) | 6 |
| Execution (LOLBins) | 10 |
| **Total** | **59** |

## Directory Structure

```
sigma/
├── persistence/
│   ├── veilhunter_run_key_persistence.yml
│   ├── veilhunter_run_key_suspicious_value.yml
│   ├── veilhunter_scheduled_task_created.yml
│   ├── veilhunter_scheduled_task_lolbin.yml
│   ├── veilhunter_service_installed.yml
│   ├── veilhunter_service_suspicious_imagepath.yml
│   ├── veilhunter_wmi_subscription_created.yml
│   ├── veilhunter_wmi_commandline_consumer.yml
│   ├── veilhunter_ifeo_debugger_hijack.yml
│   ├── veilhunter_startup_folder_drop.yml
│   ├── veilhunter_winlogon_helper_tampered.yml
│   └── veilhunter_appinit_dlls.yml
├── credential_access/
│   ├── veilhunter_lsass_memory_access.yml
│   ├── veilhunter_lsass_dumper_on_disk.yml
│   ├── veilhunter_sam_hive_access.yml
│   ├── veilhunter_kerberoasting.yml
│   ├── veilhunter_asrep_roasting.yml
│   ├── veilhunter_dpapi_master_key_access.yml
│   ├── veilhunter_browser_credential_access.yml
│   └── veilhunter_credential_file_created.yml
├── lateral_movement/
│   ├── veilhunter_psexec_service_install.yml
│   ├── veilhunter_admin_share_access.yml
│   ├── veilhunter_explicit_credential_use.yml
│   ├── veilhunter_pass_the_hash.yml
│   ├── veilhunter_wmiprvse_spawns_shell.yml
│   ├── veilhunter_rdp_brute_force.yml
│   └── veilhunter_rdp_enabled_registry.yml
├── defense_evasion/
│   ├── veilhunter_amsi_bypass_registry.yml
│   ├── veilhunter_scriptblock_logging_disabled.yml
│   ├── veilhunter_defender_disabled.yml
│   ├── veilhunter_defender_exclusion_added.yml
│   ├── veilhunter_security_log_cleared.yml
│   ├── veilhunter_system_log_cleared.yml
│   ├── veilhunter_process_masquerading.yml
│   ├── veilhunter_timestomping.yml
│   └── veilhunter_unsigned_dll_in_system32.yml
├── c2_exfil/
│   ├── veilhunter_bits_transfer_suspicious_url.yml
│   ├── veilhunter_bitsadmin_download.yml
│   ├── veilhunter_suspicious_named_pipe.yml
│   ├── veilhunter_powershell_download_cradle.yml
│   ├── veilhunter_cloud_sync_archive.yml
│   ├── veilhunter_dns_over_https_enabled.yml
│   └── veilhunter_suspicious_outbound_process.yml
├── impact/
│   ├── veilhunter_shadow_copy_deletion.yml
│   ├── veilhunter_bcdedit_recovery_disabled.yml
│   ├── veilhunter_backup_catalog_deleted.yml
│   ├── veilhunter_ransom_note_created.yml
│   ├── veilhunter_ransomware_extension.yml
│   └── veilhunter_backup_service_disabled.yml
└── execution/
    ├── veilhunter_mshta_remote_execution.yml
    ├── veilhunter_certutil_decode.yml
    ├── veilhunter_rundll32_suspicious.yml
    ├── veilhunter_regsvr32_suspicious.yml
    ├── veilhunter_wscript_cscript_suspicious.yml
    ├── veilhunter_encoded_powershell.yml
    ├── veilhunter_office_spawns_lolbin.yml
    ├── veilhunter_esentutl_credential_access.yml
    ├── veilhunter_makecab_staging.yml
    └── veilhunter_wmic_process_create.yml
```

---

## Converting Rules to Your SIEM

Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) to convert rules to your platform's query language.

### Install sigma-cli

```bash
pip install sigma-cli
pip install pySigma-backend-splunk
pip install pySigma-backend-elastic
pip install pySigma-backend-microsoft365defender
pip install pySigma-backend-qradar
pip install pySigma-backend-sentinel
```

### Convert a Single Rule

```bash
# Splunk SPL
sigma convert -t splunk -f default sigma/persistence/veilhunter_run_key_persistence.yml

# Elasticsearch / OpenSearch (EQL)
sigma convert -t elasticsearch -f eql sigma/persistence/veilhunter_run_key_persistence.yml

# Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender sigma/persistence/veilhunter_run_key_persistence.yml

# QRadar AQL
sigma convert -t qradar sigma/persistence/veilhunter_run_key_persistence.yml
```

### Convert All Rules in a Category

```bash
# All persistence rules to Splunk
sigma convert -t splunk -f default sigma/persistence/*.yml

# All rules in all categories to Sentinel KQL
sigma convert -t microsoft365defender sigma/**/*.yml
```

### Convert Everything at Once

```bash
# Convert all 59 rules to Splunk, write to output file
sigma convert -t splunk -f default sigma/**/*.yml -o veilhunter_splunk_rules.conf

# Convert all rules to Elasticsearch NDJSON
sigma convert -t elasticsearch -f ndjson sigma/**/*.yml -o veilhunter_elastic_rules.ndjson

# Convert all rules to Sentinel (KQL) and save
sigma convert -t microsoft365defender sigma/**/*.yml -o veilhunter_sentinel_rules.kql
```

---

## Log Sources Required

Different rules require different Windows log sources. Enable these for full coverage:

### Process Creation (EventID 4688)
Required by: all execution, lateral movement, and most persistence rules.
```
auditpol /set /subcategory:"Process Creation" /success:enable
```
Also enable command line logging via Group Policy:
`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events`

### Sysmon (Recommended)
Many rules are written for Sysmon categories (`process_creation`, `file_event`, `registry_set`, `network_connection`, `pipe_created`) which provide richer data than native Windows logging.

Install Sysmon with the SwiftOnSecurity configuration:
```powershell
# Download and install Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Security Log Size
Increase the Security event log maximum size to retain enough history:
```
wevtutil sl Security /ms:1073741824
```

### WMI Activity Log
Required by WMI subscription rules:
```
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
```

### BITS Client Log
Required by BITS transfer rules:
```
wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true
```

### Task Scheduler Log
Required by scheduled task rules:
```
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

### Kerberos Auditing
Required by Kerberoasting and AS-REP roasting rules:
```
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

---

## Rule Levels

| Level | Meaning |
|-------|---------|
| `critical` | Near-zero false positives. Requires immediate investigation. |
| `high` | Strong indicator of malicious activity. Low expected false positive rate. |
| `medium` | Suspicious activity that may have legitimate explanations. Requires context. |
| `low` | Informational. Used for baselining and anomaly detection. |

---

## Mapping to VeilHunter Scripts

| SIGMA Category | VeilHunter Script |
|----------------|------------------|
| persistence/ | Veil_Hunter_v2.ps1, Task_Hunter_v2.ps1, service_installs_v2.ps1 |
| credential_access/ | VH_Credential_Hunter.ps1 |
| lateral_movement/ | VH_Lateral_Hunter.ps1 |
| defense_evasion/ | VH_Defense_Evasion_Hunter.ps1 |
| c2_exfil/ | VH_C2_Exfil_Hunter.ps1 |
| impact/ | VH_PreRansom_Hunter.ps1 |
| execution/ | VH_LOLBin_Hunter.ps1, malvertising_payload_hunter_v2.ps1 |

---

## Tuning Guidance

### Reducing False Positives

Most rules include `filter_` conditions for common legitimate use cases. Before deploying:

1. Run the rule in detection-only mode against 30 days of historical data
2. Review all matches and identify legitimate activity patterns in your environment
3. Add environment-specific exclusions to the `filter_` conditions
4. Promote to alerting only after a clean baseline period

### High-Priority Rules (Deploy First)

These rules have near-zero legitimate false positives and should be deployed immediately:

- `veilhunter_lsass_dumper_on_disk.yml` — mimikatz/procdump on disk
- `veilhunter_ransom_note_created.yml` — ransom note file names
- `veilhunter_ransomware_extension.yml` — known ransomware extensions
- `veilhunter_office_spawns_lolbin.yml` — Office macro → LOLBin chain
- `veilhunter_process_masquerading.yml` — svchost/lsass outside System32
- `veilhunter_suspicious_named_pipe.yml` — C2 framework named pipes
- `veilhunter_wmi_subscription_created.yml` — WMI permanent subscription

### Rules Requiring Tuning Before Deployment

These rules will generate noise in most environments without tuning:

- `veilhunter_admin_share_access.yml` — tune for your management subnet
- `veilhunter_pass_the_hash.yml` — add exclusions for expected NTLM sources
- `veilhunter_scheduled_task_created.yml` — allowlist known software task names
- `veilhunter_service_installed.yml` — allowlist your deployment tools

---

## License

Apache 2.0 — see [LICENSE](../LICENSE) for details.
