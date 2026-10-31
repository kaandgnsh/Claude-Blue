---
name: sigma-conversion
description: Convert Sigma rules to SIEM/EDR query languages with sigma-cli and pySigma backends (Splunk, Microsoft Sentinel/Defender KQL, Elastic, QRadar, etc.), choose processing pipelines for field mapping, and review converted queries for correctness and performance. Use when deploying Sigma rules to a specific platform or troubleshooting conversion output.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: tested
---

# Sigma Conversion

## Install backends as plugins

```sh
pip install sigma-cli
sigma plugin list                 # available backends/pipelines
sigma plugin install splunk       # pySigma-backend-splunk
sigma plugin install kusto        # Microsoft Sentinel / Defender XDR (KQL)
sigma plugin install elasticsearch
sigma list targets ; sigma list pipelines
```
Backend and pySigma versions must be compatible — pin both in your detection-as-code repo (a mismatched backend fails at import time).

## Convert

```sh
# Splunk with Windows source mapping
sigma convert -t splunk -p splunk_windows rules/windows/process_creation/
# Splunk CIM data model (tstats-friendly)
sigma convert -t splunk -p splunk_cim -f data_model rules/windows/process_creation/
# Microsoft Defender XDR advanced hunting
sigma convert -t kusto -p microsoft_xdr rules/windows/process_creation/
# Elastic (ECS field names)
sigma convert -t lucene -p ecs_windows rules/
```
Run `sigma convert --help` and `sigma list formats <target>` for output formats (e.g. `savedsearches` for Splunk, `ndjson` for Elastic detection rules). Pipeline names vary by backend version.

## Review converted output

1. **Field mapping**: every Sigma field mapped to a real field in your data (e.g. `Image` → `process_path` in your Splunk add-on?). Unmapped fields silently produce queries that never match. Write a custom pipeline YAML for your schema:
   ```yaml
   name: corp-edr-mapping
   priority: 30
   transformations:
     - id: field_map
       type: field_name_mapping
       mapping:
         Image: process_path
         CommandLine: process_cmdline
         ParentImage: parent_process_path
   ```
   Use with `-p splunk_windows -p corp_pipeline.yml`.
2. **Index/table scoping**: add index/sourcetype or table constraints for performance.
3. **Case sensitivity & wildcards**: leading wildcards are expensive in Splunk/Elastic; prefer `endswith` on a normalized field or tstats.
4. **Run it** against a positive test event and over 24h to gauge volume (`detection-testing`).

## Related skills

`sigma-authoring`, `detection-as-code`, `field-normalization`, `query-performance`

## References

- sigma-cli: https://github.com/SigmaHQ/sigma-cli
- pySigma processing pipelines: https://sigmahq-pysigma.readthedocs.io/en/latest/
- pySigma backends list: https://sigmahq.io/docs/digging-deeper/backends.html
