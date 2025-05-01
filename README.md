## Resource List

- `Windows_MITRE_Data_Source_Mapping.xlsx`
  - Maps each Windows Advanced Audit Log Setting to its corresponding MITRE data source and Event IDs
  - For more information, see: https://blog.blacklanternsecurity.com/p/mapping-windows-audit-log-settings
- `Analyze-AuditPolicies.ps1`
  - Analyzes system audit policies and optionally compares them with a set security baseline
  - `iex ((New-Object System.Net.WebClient).DownloadString("https://github.com/blacklanternsecurity/blue-resources/raw/refs/heads/main/Analyze-AuditPolicies.ps1"))`
