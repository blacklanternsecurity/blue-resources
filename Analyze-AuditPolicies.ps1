# Auditing Constants - https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants
# NOTE: MS documentation contains incomplete list, full list is defined in the "NTSecAPI.h" header
$AuditCategories = @{
    Audit_AccountLogon = "69979850-797a-11d9-bed3-505054503030"
    Audit_AccountManagement = "6997984e-797a-11d9-bed3-505054503030"
    Audit_DetailedTracking = "6997984c-797a-11d9-bed3-505054503030"
    Audit_DirectoryServiceAccess = "6997984f-797a-11d9-bed3-505054503030"
    Audit_Logon = "69979849-797a-11d9-bed3-505054503030"
    Audit_ObjectAccess = "6997984a-797a-11d9-bed3-505054503030"
    Audit_PolicyChange = "6997984d-797a-11d9-bed3-505054503030"
    Audit_PrivilegeUse = "6997984b-797a-11d9-bed3-505054503030"
    Audit_System = "69979848-797a-11d9-bed3-505054503030"
}
$AuditSubCategories = @{
    Audit_AccountLogon_CredentialValidation = "0cce923f-69ae-11d9-bed3-505054503030"
    Audit_AccountLogon_KerbCredentialValidation = "0cce9242-69ae-11d9-bed3-505054503030"
    Audit_AccountLogon_Kerberos = "0cce9240-69ae-11d9-bed3-505054503030"
    Audit_AccountLogon_Others = "0cce9241-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_ApplicationGroup = "0cce9239-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_ComputerAccount = "0cce9236-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_DistributionGroup = "0cce9238-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_Others = "0cce923a-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_SecurityGroup = "0cce9237-69ae-11d9-bed3-505054503030"
    Audit_AccountManagement_UserAccount = "0cce9235-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_DpapiActivity = "0cce922d-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_PnpActivity = "0cce9248-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_ProcessCreation = "0cce922b-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_ProcessTermination = "0cce922c-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_RpcCall = "0cce922e-69ae-11d9-bed3-505054503030"
    Audit_DetailedTracking_TokenRightAdjusted = "0cce924a-69ae-11d9-bed3-505054503030"
    Audit_Ds_DetailedReplication = "0cce923e-69ae-11d9-bed3-505054503030"
    Audit_Ds_Replication = "0cce923d-69ae-11d9-bed3-505054503030"
    Audit_DsAccess_AdAuditChanges = "0cce923c-69ae-11d9-bed3-505054503030"
    Audit_DSAccess_DSAccess = "0cce923b-69ae-11d9-bed3-505054503030"
    Audit_Logon_AccountLockout = "0cce9217-69ae-11d9-bed3-505054503030"
    Audit_Logon_Claims = "0cce9247-69ae-11d9-bed3-505054503030"
    Audit_Logon_Groups = "0cce9249-69ae-11d9-bed3-505054503030"
    Audit_Logon_IPSecMainMode = "0cce9218-69ae-11d9-bed3-505054503030"
    Audit_Logon_IPSecQuickMode = "0cce9219-69ae-11d9-bed3-505054503030"
    Audit_Logon_IPSecUserMode = "0cce921a-69ae-11d9-bed3-505054503030"
    Audit_Logon_Logoff = "0cce9216-69ae-11d9-bed3-505054503030"
    Audit_Logon_Logon = "0cce9215-69ae-11d9-bed3-505054503030"
    Audit_Logon_NPS = "0cce9243-69ae-11d9-bed3-505054503030"
    Audit_Logon_Others = "0cce921c-69ae-11d9-bed3-505054503030"
    Audit_Logon_SpecialLogon = "0cce921b-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_ApplicationGenerated = "0cce9222-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_CbacStaging = "0cce9246-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_CertificationServices = "0cce9221-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_DetailedFileShare = "0cce9244-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_FileSystem = "0cce921d-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_FirewallConnection = "0cce9226-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_FirewallPacketDrops = "0cce9225-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Handle = "0cce9223-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Kernel = "0cce921f-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Other = "0cce9227-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Registry = "0cce921e-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_RemovableStorage = "0cce9245-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Sam = "0cce9220-69ae-11d9-bed3-505054503030"
    Audit_ObjectAccess_Share = "0cce9224-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_AuditPolicy = "0cce922f-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_AuthenticationPolicy = "0cce9230-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_AuthorizationPolicy = "0cce9231-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_MpsscvRulePolicy = "0cce9232-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_Others = "0cce9234-69ae-11d9-bed3-505054503030"
    Audit_PolicyChange_WfpIPSecPolicy = "0cce9233-69ae-11d9-bed3-505054503030"
    Audit_PrivilegeUse_NonSensitive = "0cce9229-69ae-11d9-bed3-505054503030"
    Audit_PrivilegeUse_Others = "0cce922a-69ae-11d9-bed3-505054503030"
    Audit_PrivilegeUse_Sensitive = "0cce9228-69ae-11d9-bed3-505054503030"
    Audit_System_Integrity = "0cce9212-69ae-11d9-bed3-505054503030"
    Audit_System_IPSecDriverEvents = "0cce9213-69ae-11d9-bed3-505054503030"
    Audit_System_Others = "0cce9214-69ae-11d9-bed3-505054503030"
    Audit_System_SecurityStateChange = "0cce9210-69ae-11d9-bed3-505054503030"
    Audit_System_SecuritySubsystemExtension = "0cce9211-69ae-11d9-bed3-505054503030"	
}

# Configurable baseline configuration
$securityBaseline = @(
    [PSCustomObject]@{ GUID = $AuditCategories.Audit_AccountLogon; AuditEvents = 'S','F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_AccountManagement_ComputerAccount; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_AccountManagement_Others; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_AccountManagement_SecurityGroup; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_AccountManagement_UserAccount; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_DetailedTracking_PnpActivity; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_DetailedTracking_ProcessCreation; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_DetailedTracking_TokenRightAdjusted; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_DSAccess_DSAccess; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_DsAccess_AdAuditChanges; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_AccountLockout; AuditEvents = 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_Logoff; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_Logon; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_NPS; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_Others; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_Logon_SpecialLogon; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_ObjectAccess_CertificationServices; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_ObjectAccess_Share; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_ObjectAccess_FileSystem; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_ObjectAccess_Other; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_ObjectAccess_Registry; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_PolicyChange_AuditPolicy; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_PolicyChange_AuthenticationPolicy; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_PolicyChange_AuthorizationPolicy; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_PrivilegeUse_Sensitive; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_System_IPSecDriverEvents; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_System_Others; AuditEvents = 'S', 'F' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_System_SecurityStateChange; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_System_SecuritySubsystemExtension; AuditEvents = 'S' }
    [PSCustomObject]@{ GUID = $AuditSubCategories.Audit_System_Integrity; AuditEvents = 'S', 'F' }
)


$AuditPolicyReader = Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

public class AuditPolicyReader {
    [Flags]
    public enum POLICY_AUDIT_EVENT_OPTIONS {
        POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000,
        POLICY_AUDIT_EVENT_SUCCESS = 0x00000001,
        POLICY_AUDIT_EVENT_FAILURE = 0x00000002,
        POLICY_AUDIT_EVENT_NONE = 0x00000004,
        PER_USER_POLICY_UNCHANGED = 0x00,
        PER_USER_AUDIT_SUCCESS_INCLUDE = 0x01,
        PER_USER_AUDIT_SUCCESS_EXCLUDE = 0x02,
        PER_USER_AUDIT_FAILURE_INCLUDE = 0x04,
        PER_USER_AUDIT_FAILURE_EXCLUDE = 0x08,
        PER_USER_AUDIT_NONE = 0x10
    }

    public struct AUDIT_POLICY_INFORMATION {
        public Guid AuditSubCategoryGuid;
        public UInt32 AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll")]
    public static extern bool AuditEnumerateCategories(out IntPtr catList, out uint count);
    
    [DllImport("advapi32.dll")]
    public static extern bool AuditLookupCategoryName(Guid catGuid, out string catName);
    
    [DllImport("advapi32.dll")]
    public static extern bool AuditEnumerateSubCategories(Guid catGuid, bool all, out IntPtr subList, out uint count);
    
    [DllImport("advapi32.dll")]
    public static extern bool AuditLookupSubCategoryName(Guid subGuid, out String subName);
    
    [DllImport("advapi32.dll")]
    public static extern bool AuditQuerySystemPolicy(Guid subGuid, uint count, out IntPtr policy);
    
    [DllImport("advapi32.dll")]
    public static extern void AuditFree(IntPtr buffer);
    

    public static Dictionary<Guid, string> GetAuditCategories() {
        IntPtr buffer = IntPtr.Zero;
        uint count = 0;
        var size = Marshal.SizeOf(typeof(Guid));

        if (!AuditEnumerateCategories(out buffer, out count)) {
            throw new Exception("[!] Failed to enumerate audit categories!");
        }

        IntPtr currentPtr = buffer;
        Dictionary<Guid, string> auditCategories = new Dictionary<Guid, string>();

        for (uint i = 0; i < count; i++) {
            Guid guid = Marshal.PtrToStructure<Guid>(currentPtr);
            string name;
            AuditLookupCategoryName(guid, out name);
            auditCategories[guid] = name;
            currentPtr += size;
        }

        AuditFree(buffer);
        return auditCategories;
    }


    public static Dictionary<Guid, object> GetAuditSubCategories() {
        IntPtr buffer = IntPtr.Zero;
        uint count = 0;
        var size = Marshal.SizeOf(typeof(Guid));
        Guid emptyGuid = Guid.Empty;

        if (!AuditEnumerateSubCategories(emptyGuid, true, out buffer, out count)) {
            throw new Exception("[!] Failed to enumerate audit subcategories!");
        }

        IntPtr currentPtr = buffer;
        Dictionary<Guid, object> auditSubCategories = new Dictionary<Guid, object>();

        for (uint i = 0; i < count; i++) {
            Guid guid = Marshal.PtrToStructure<Guid>(currentPtr);
            string subCategoryname;
            AuditLookupSubCategoryName(guid, out subCategoryname);

            AUDIT_POLICY_INFORMATION pol = new AUDIT_POLICY_INFORMATION();
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(pol));
            Marshal.StructureToPtr(pol, ptr, false);
    
            if (!AuditQuerySystemPolicy(guid, 1, out ptr)) {
                throw new Exception("[!] Failed to query system audit policy!");
            }

            pol = Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(ptr);
            Marshal.FreeHGlobal(ptr);

            string categoryName;
            AuditLookupCategoryName(pol.AuditCategoryGuid, out categoryName);

            // Workaround to prevent extraneous display of 0'd flag
            string auditEvents = ((POLICY_AUDIT_EVENT_OPTIONS)pol.AuditingInformation).ToString();
            if (pol.AuditingInformation != 0) {
                auditEvents = auditEvents.Replace("POLICY_AUDIT_EVENT_UNCHANGED, ", string.Empty).Replace("PER_USER_POLICY_UNCHANGED, ", string.Empty);
            }

            auditSubCategories[guid] = new {
                CategoryGUID = pol.AuditCategoryGuid,
                Category = categoryName,
                Subcategory = subCategoryname,
                AuditInfoInternal = pol.AuditingInformation,
                AuditInfo = auditEvents,
            };

            currentPtr += size;
        }

        AuditFree(buffer);
        return auditSubCategories;
    }
}
'@ -PassThru | Where-Object Name -eq AuditPolicyReader


function Analyze-AuditPolicies {
    <#
    .SYNOPSIS
    Analyzes the system audit policies and optionally compares them with a set security baseline.

    .DESCRIPTION
    Retrieves the current local or advanced audit policies configured on the system.

    .PARAMETER Test
    All settings in the security baseline are tested and output.

    .EXAMPLE
    Analyze-AuditPolicies
    Lists the configuration of all audit policy categories and subcategories on the system.

    .EXAMPLE
    Analyze-AuditPolicies -Test
    Compares the current audit policy configuration with the security baseline and outputs the results.
    #>

    [CmdletBinding()]
    param (
        [switch]$Test
    )

    try {
        $auditCategoryList = $AuditPolicyReader::GetAuditCategories()
        $auditSubCategoryList = $AuditPolicyReader::GetAuditSubCategories()

        if (-not $Test) {
            $auditSubCategoryList.Values | Sort-Object Category, Subcategory | Format-Table Category, Subcategory, AuditInfo
        }

        else {
            $passedRules = @()
            $failedRules = @()

            foreach ($b in $securityBaseline) {
                if ($AuditCategories.ContainsValue($b.GUID)) {
                    $matchingCategory = $auditCategoryList[$b.GUID]
                    $matchingSettings = $auditSubCategoryList.Values | Where-Object { $_.CategoryGUID -eq $b.GUID }
                }
                elseif ($AuditSubCategories.ContainsValue($b.GUID)) {
                    $matchingSettings = @($auditSubCategoryList[$b.GUID])
                }
                else {
                    Write-Error "[!] Invalid security baseline"
                    return
                }

                foreach ($s in $matchingSettings) {
                    $auditSetting = [AuditPolicyReader+POLICY_AUDIT_EVENT_OPTIONS]$s.AuditInfoInternal

                    if ($b.AuditEvents.Contains('S')) {
                        if (-not ($auditSetting.HasFlag([AuditPolicyReader+POLICY_AUDIT_EVENT_OPTIONS]::POLICY_AUDIT_EVENT_SUCCESS) -or $auditSetting.HasFlag([AuditPolicyReader+POLICY_AUDIT_EVENT_OPTIONS]::PER_USER_AUDIT_SUCCESS_INCLUDE))) {
                            $failedRules += [PSCustomObject]@{
                                Category = $s.Category
                                Subcategory = $s.Subcategory
                                Baseline = $b.AuditEvents
                                Current = $s.AuditInfo
                            }
                            continue
                        }
                    }
                    if ($b.AuditEvents.Contains('F')) {
                        if (-not ($auditSetting.HasFlag([AuditPolicyReader+POLICY_AUDIT_EVENT_OPTIONS]::POLICY_AUDIT_EVENT_FAILURE) -or $auditSetting.HasFlag([AuditPolicyReader+POLICY_AUDIT_EVENT_OPTIONS]::PER_USER_AUDIT_FAILURE_INCLUDE))) {
                            $failedRules += [PSCustomObject]@{
                                Category = $s.Category
                                Subcategory = $s.Subcategory
                                Baseline = $b.AuditEvents
                                Current = $s.AuditInfo
                            }
                            continue
                        }
                    }

                    $passedRules += [PSCustomObject]@{
                        Category = $s.Category
                        Subcategory = $s.Subcategory
                        Baseline = $b.AuditEvents
                        Current = $s.AuditInfo
                    }
                }
            }

            $passedOutput = $passedRules | Format-List -Property Category, Subcategory, Current, Baseline | Out-String
            Write-Host ("Passed Rules:") -ForegroundColor Green
            switch -regex ($passedOutput -split '\r?\n') {
                '^Current\s*:' { 
                        $label,$value = $_ -split ':',2 
                        Write-Host ($label + ":") -NoNewline
                        Write-Host $value -ForegroundColor Green
                }
                '^Baseline\s*:' { 
                        $label,$value = $_ -split ':',2 
                        Write-Host ($label + ":") -NoNewline
                        Write-Host $value -ForegroundColor Green
                }
                default { $_ }
            }

            $failedOutput = $failedRules | Format-List -Property Category, Subcategory, Current, Baseline | Out-String
            Write-Host ("Failed Rules:") -ForegroundColor Red
            switch -regex ($failedOutput -split '\r?\n') {
                '^Current\s*:' { 
                        $label,$value = $_ -split ':',2 
                        Write-Host ($label + ":") -NoNewline
                        Write-Host $value -ForegroundColor Red
                }
                '^Baseline\s*:' { 
                        $label,$value = $_ -split ':',2 
                        Write-Host ($label + ":") -NoNewline
                        Write-Host $value -ForegroundColor Yellow
                }
                default { $_ }
            }
        }
    } 
    catch {
        Write-Error "An error occurred: $_"
    }
}


Analyze-AuditPolicies -?