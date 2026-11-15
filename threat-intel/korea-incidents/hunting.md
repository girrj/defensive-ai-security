# Korean case hunting guide (국내 사례 헌팅 가이드)

These are **defensive starting points**, not evidence that a named victim had the same telemetry. Replace every `<placeholder>` with a locally validated index, UDM field, event value, allow-list or threshold before use. Limit the time window, verify parser mappings against raw records, and investigate results with the linked case. A hit is a lead, not attribution. Keep sensitive identifiers out of shared query results.

Splunk examples use SPL. Google SecOps examples use UDM Search filters; use its statistics view to group and compare results where noted. The local parser must map the named event to UDM before that search can work. See the repository's [SPL](../../hunting/splunk-spl.md) and [UDM](../../hunting/google-secops-udm.md) guides and the [Google UDM search reference](https://cloud.google.com/chronicle/docs/investigation/search-syntax-reference).

## bpfdoor

**Question:** Which Linux hosts show unexpected packet-socket processes or the BPFDoor artifacts already covered by this repository? Review command and process ancestry; do not treat an absent listening port as clearance. See [case 01](cases/01-skt-usim-bpfdoor.md) and the [Sigma artifact rule](../../detections/sigma/bpfdoor_pid_file_artifacts.yml).

```spl
index=<linux_endpoint_index> <event_type_field>=<process_or_file_event>
| search <artifact_field>=<approved_bpfdoor_artifact_pattern>
| stats count min(_time) as first max(_time) as last values(<process_field>) as processes by <host_field> <artifact_field>
```

```text
<event_type_field> = "<process_or_file_event>" AND
<artifact_field> = /<approved_bpfdoor_artifact_pattern>/
```

## rogue-device-registration

**Question:** Did a device identity register from an unapproved network, geography or certificate? Join registration logs to the authoritative device inventory and revoke cloned identities. See [case 02](cases/02-kt-femtocell-and-servers.md).

```spl
index=<device_registration_index> <result_field>=<success_value>
| lookup <approved_device_inventory> <device_id_field> OUTPUT <approved_network_field>
| where isnull(<approved_network_field>) OR <source_network_field>!=<approved_network_field>
| stats count values(<source_network_field>) as sources by <device_id_field> <certificate_id_field>
```

```text
<event_type_field> = "<device_registration_event>" AND
<result_field> = "<success_value>"
```

In UDM results, compare device and certificate identifiers with the approved inventory and source network.

## pam-vault-anomalies

**Question:** Which privileged credential or vault export events differ from the approved change window and owner? Correlate vault access with host logons and preserve audit logs. See [case 03](cases/03-lgu-appm-leak.md).

```spl
index=<pam_audit_index> <action_field> IN (<checkout_value>,<export_value>)
| stats count dc(<secret_id_field>) as secrets values(<target_field>) as targets by <user_field> <source_ip_field>
| where secrets><review_threshold>
```

```text
<event_type_field> = "<vault_access_event>" AND
<action_field> = "<checkout_or_export_value>"
```

## vpn-new-source

**Question:** Was a certificate or user used from a new source or device? Compare against the user's own approved history, then validate MFA and certificate revocation. See [case 04](cases/04-onnara-gpki.md).

```spl
index=<vpn_index> <result_field>=<success_value>
| stats min(_time) as first_seen dc(<source_ip_field>) as sources values(<device_field>) as devices by <user_field> <certificate_id_field> <source_ip_field>
| where first_seen>=relative_time(now(), "-<lookback_days>d")
```

```text
<event_type_field> = "<vpn_login_event>" AND
<result_field> = "<success_value>"
```

Compare the returned source and device with the approved baseline; the SPL `first_seen` value covers only the selected search range.

## vpn-brute-force

**Question:** Are repeated failed appliance logons followed by success? Check rate limits, default accounts and the management interface. See [case 06](cases/06-sgi-gunra-ransomware.md).

```spl
index=<vpn_or_appliance_index> <event_type_field>=<login_event>
| bin _time span=15m
| stats count(eval(<result_field>=<failure_value>)) as failures count(eval(<result_field>=<success_value>)) as successes by _time <source_ip_field> <user_field>
| where failures>=<review_threshold> OR (failures>0 AND successes>0)
```

```text
<event_type_field> = "<login_event>" AND
<result_field> = "<failure_or_success_value>"
```

Group UDM results by source, user and a short time window; look for failure-to-success sequences.

## ioc-sweep

**Question:** Do current logs match public, defanged indicators in [the IOC CSV](iocs/iocs.csv)? Refang only inside a controlled local lookup, preserve `scope`, and treat campaign indicators as campaign leads rather than case proof. See [case 06](cases/06-sgi-gunra-ransomware.md) and [case 11](cases/11-korean-air-kcd-oracle-ebs.md).

```spl
index=<network_or_endpoint_index>
| lookup <locally_refanged_ioc_lookup> <observable_field> OUTPUT scope source_url case
| where isnotnull(scope)
| stats count values(scope) as scope values(source_url) as sources by <observable_field> <host_field>
```

```text
<observable_field> = "<one_locally_refanged_public_ioc>"
```

## weblogic

**Question:** Did a WebLogic host show an unusual application request followed by an unexpected Java child process? Apply the vendor fix and review historical logs, not just current WAF blocks. See [case 07](cases/07-lotte-card-weblogic.md) and [vulnerabilities](vulnerabilities.md).

```spl
index=<endpoint_index> <parent_process_field>=<weblogic_java_process>
| search <child_process_field> IN (<shell_value>,<download_tool_value>)
| stats count values(<command_line_field>) as commands by <host_field> <parent_process_field> <child_process_field>
```

```text
<event_type_field> = "<process_launch_event>" AND
<parent_process_field> = "<weblogic_java_process>" AND
<child_process_field> = /<unexpected_child_process_pattern>/
```

## credential-stuffing

**Question:** Is one source trying many accounts, with a success after failures? Separate shared egress and accessibility tools before blocking; add MFA and rate limits. See [case 08](cases/08-gs-retail-credential-stuffing.md).

```spl
index=<identity_index> <event_type_field>=<login_event>
| bin _time span=15m
| stats dc(<user_field>) as users count(eval(<result_field>=<failure_value>)) as failures count(eval(<result_field>=<success_value>)) as successes by _time <source_ip_field>
| where users>=<user_threshold> AND failures>=<failure_threshold>
```

```text
<event_type_field> = "<login_event>" AND
<result_field> = "<failure_or_success_value>"
```

Group UDM results by source and count distinct users; inspect any later successes.

## token-key-misuse

**Question:** Are signed tokens using an unknown key ID, unexpected issuer or unusually broad account access? Validate the signature and claims in the application; a log query alone cannot prove validity. See [case 09](cases/09-coupang-signing-key.md).

```spl
index=<application_auth_index> <event_type_field>=<token_validation_event>
| lookup <approved_signing_key_ids> <key_id_field> OUTPUT <approved_issuer_field>
| where isnull(<approved_issuer_field>) OR <issuer_field>!=<approved_issuer_field>
| stats count dc(<account_field>) as accounts by <key_id_field> <issuer_field> <source_ip_field>
```

```text
<event_type_field> = "<token_validation_event>" AND
<result_field> = "<accepted_value>"
```

Compare UDM key ID and issuer to the current signing-key inventory. Avoid logging full bearer tokens.

## hot-wallet-withdrawals

**Question:** Is a withdrawal destination outside the approved address set, or is volume outside the wallet's normal operating range? Pause and independently verify before releasing funds. See [case 10](cases/10-upbit-hot-wallet.md).

```spl
index=<wallet_audit_index> <event_type_field>=<withdrawal_event>
| lookup <approved_destinations> <destination_field> OUTPUT <approval_field>
| where isnull(<approval_field>)
| stats count sum(<amount_field>) as total by <wallet_field> <destination_field>
```

```text
<event_type_field> = "<withdrawal_event>" AND
<status_field> = "<submitted_or_approved_value>"
```

Compare UDM destinations and amounts with the approved list and independent ledger. Do not put private keys in logs.

## oracle-ebs

**Question:** Did an EBS server show an unusual application request, changed template or unexpected child process? Scope from the [Oracle advisories](vulnerabilities.md) and [case 11](cases/11-korean-air-kcd-oracle-ebs.md); do not infer a specific CVE from one request.

```spl
index=<ebs_audit_or_endpoint_index> <event_type_field> IN (<template_change_event>,<process_launch_event>)
| stats count values(<object_or_process_field>) as objects by <host_field> <user_field>
```

```text
<event_type_field> = "<template_change_or_process_launch_event>" AND
<asset_field> = /<approved_ebs_asset_pattern>/
```

## access-key-and-bulk-read

**Question:** Was a developer key used from a new source and followed by a large read or export? Alert on both successful and blocked attempts, rotate affected keys and preserve audit logs. See [case 12](cases/12-tving-access-key.md).

```spl
index=<cloud_or_database_audit_index> <event_type_field> IN (<key_use_event>,<bulk_read_event>)
| stats count sum(<rows_read_field>) as rows dc(<source_ip_field>) as sources values(<event_type_field>) as events by <key_id_field> <actor_field>
| where rows>=<review_threshold> OR sources>1
```

```text
<event_type_field> = "<key_use_or_bulk_read_event>" AND
<result_field> = "<success_or_blocked_value>"
```

## References

- [Google SecOps UDM Search syntax](https://cloud.google.com/chronicle/docs/investigation/search-syntax-reference)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK: Data Sources](https://attack.mitre.org/datasources/)
- Case-specific public sources are listed in the linked case files.
