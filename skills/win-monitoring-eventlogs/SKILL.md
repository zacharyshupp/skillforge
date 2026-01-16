---
name: Windows Event Logs
description: Investigate Windows system issues using Event Logs. Use this skill when diagnosing reboots, service failures, account lockouts, application crashes, security events, or suspicious changes. Produces structured, repeatable investigation workflows.
---

# Windows Event Logs Investigation

This skill provides investigation workflows for Windows Event Logs - not just cmdlet syntax, but structured approaches that produce consistent, actionable results.

## Claude Code Behavior Guidelines

### MANDATORY RULES (Follow Exactly)

**STOP AFTER ONE COMMAND.** When querying or exporting event logs:

1. Run exactly ONE PowerShell command
2. Report the result to the user
3. STOP. Do not run any verification, follow-up, or confirmation commands.

**NEVER do these things:**

- NEVER verify file existence after export (no `Test-Path`, `Get-Item`, `Get-ChildItem`)
- NEVER count lines or measure file size after export
- NEVER read the file back after writing it
- NEVER create .ps1 script files
- NEVER wrap PowerShell in bash
- NEVER use multi-line commands

**ALWAYS do these things:**

- Run PowerShell commands directly (not through bash)
- Use single-line commands only
- Report the command output and STOP

### Investigation Guidelines

1. **Ask the user for:** timeframe, target computer(s), symptom description
2. **Default to read-only** - never enable logs or change audit policy unless explicitly requested
3. **Never dump raw Message blobs** - summarize findings and include `RecordId` for follow-up queries

### Command Execution

**Use single-line PowerShell commands. Examples:**

**Preferred execution patterns:**

```powershell
# Pattern 1: FilterHashtable with semicolon-separated key-value pairs (simplest)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50

# Pattern 2: FilterXPath for complex filtering (most reliable, no hashtable issues)
Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=41 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= 604800000]]]" -MaxEvents 50
```

**Copy-paste ready queries (use these exact commands):**

```powershell
# Recent errors from System log (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Format-Table -Wrap

# Unexpected reboots (last 7 days)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008,1074,6005,6006; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-Table -Wrap

# Failed logins (last 24 hours) - requires admin
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-Table -Wrap

# Service crashes (last 7 days)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7031,7034; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-Table -Wrap

# Application errors (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, Message | Format-Table -Wrap
```

**If a command fails, try the XPath alternative:**

```powershell
# XPath version of reboot query (no hashtable parsing)
Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=41 or EventID=6008 or EventID=1074)]]" -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
```

---

## Investigation Hygiene Checklist

Before starting any investigation:

- [ ] **Document scope:** timeframe, target host(s), symptom description
- [ ] **Verify access:** admin rights, Event Log Readers membership, WinRM/RPC connectivity
- [ ] **Export first:** if this is incident response, export .evtx before any changes
- [ ] **Record filters:** log every query (log name, IDs, time range, count returned)
- [ ] **Preserve evidence:** never clear, restart services, or enable logs without explicit approval

After investigation:

- [ ] **Summarize findings:** top event IDs, providers, sample messages
- [ ] **Include counts:** "Found 47 errors from 3 providers over 24 hours"
- [ ] **Provide export path:** if offline analysis was used

---

## Core Function: Get-EventLogData

Use this reusable wrapper for consistent, safe queries with full correlation fields:

```powershell
function Get-EventLogData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Live')]
        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [Parameter(Mandatory, ParameterSetName = 'Offline')]
        [string[]]$LogName,

        [Parameter(Mandatory, ParameterSetName = 'Offline')]
        [string]$Path,

        [Parameter(ParameterSetName = 'Remote')]
        [string]$ComputerName,

        [Parameter(ParameterSetName = 'Remote')]
        [PSCredential]$Credential,

        [int[]]$Id,

        [ValidateSet(1,2,3,4,5)]
        [int[]]$Level,

        [string]$ProviderName,

        [datetime]$StartTime = (Get-Date).AddHours(-24),

        [datetime]$EndTime = (Get-Date),

        [int]$MaxEvents = 500,

        [switch]$IncludeFullMessage,

        [switch]$IncludeXml,

        [switch]$IncludeSourceEvent
    )

    # Build filter hashtable
    $filter = @{
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    # Path-based queries don't use LogName in filter
    if (-not $Path) {
        $filter['LogName'] = $LogName
    }

    if ($Id) { $filter['Id'] = $Id }
    if ($Level) { $filter['Level'] = $Level }
    if ($ProviderName) { $filter['ProviderName'] = $ProviderName }

    # Build Get-WinEvent parameters
    $params = @{
        FilterHashtable = $filter
        MaxEvents       = $MaxEvents
    }

    if ($Path) {
        $params['Path'] = $Path
    }
    elseif ($ComputerName) {
        $params['ComputerName'] = $ComputerName
        if ($Credential) {
            $params['Credential'] = $Credential
        }
    }

    # Execute with controlled error handling
    $events = $null
    $errorCount = 0

    try {
        $events = Get-WinEvent @params -ErrorAction Stop
    }
    catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            Write-Verbose "No events matched the filter criteria"
            return
        }
        elseif ($_.Exception.Message -match 'access is denied|privilege') {
            Write-Warning "Access denied. Verify admin rights or Event Log Readers membership."
            throw
        }
        elseif ($_.Exception.Message -match 'RPC server|network path') {
            Write-Warning "Remote connection failed. Check connectivity, firewall, and WinRM/RPC configuration."
            throw
        }
        else {
            Write-Warning "Query failed: $($_.Exception.Message)"
            throw
        }
    }

    # Process events with full correlation fields
    $events | ForEach-Object {
        $event = $_

        # Build output with correlation-friendly fields
        $output = [PSCustomObject]@{
            RecordId          = $event.RecordId
            TimeCreated       = $event.TimeCreated
            MachineName       = $event.MachineName
            LogName           = $event.LogName
            ProviderName      = $event.ProviderName
            Id                = $event.Id
            LevelValue        = $event.Level
            LevelName         = $event.LevelDisplayName
            TaskName          = $event.TaskDisplayName
            OpcodeName        = $event.OpcodeDisplayName
            Keywords          = ($event.KeywordsDisplayNames -join ', ')
            ProcessId         = $event.ProcessId
            ThreadId          = $event.ThreadId
            UserId            = if ($event.UserId) { $event.UserId.Value } else { $null }
            ActivityId        = $event.ActivityId
            RelatedActivityId = $event.RelatedActivityId
            MessageShort      = if ($event.Message) { ($event.Message -split "`n")[0].Trim() } else { '[No message]' }
        }

        if ($IncludeFullMessage) {
            $output | Add-Member -NotePropertyName 'MessageFull' -NotePropertyValue $event.Message
        }

        if ($IncludeXml) {
            $output | Add-Member -NotePropertyName 'Xml' -NotePropertyValue $event.ToXml()
        }

        if ($IncludeSourceEvent) {
            $output | Add-Member -NotePropertyName 'SourceEvent' -NotePropertyValue $event
        }

        $output
    }
}
```

**Why this wrapper:**

- **Correlation fields included:** MachineName, ProcessId, ThreadId, UserId, ActivityId for cross-log correlation
- **Path support:** Query offline .evtx files with `-Path` (mutually exclusive with -ComputerName)
- **Controlled errors:** Meaningful messages for access denied, network failures, empty results
- **Dual level output:** Both `LevelValue` (numeric) and `LevelName` (string) for sorting and display
- **Conservative defaults:** MaxEvents=500 prevents runaway queries on large Security logs
- **Optional full data:** `-IncludeFullMessage`, `-IncludeXml`, `-IncludeSourceEvent` when you need more

---

## Field Extraction Helpers

### Get-EventDataValue (XML-based, reliable)

```powershell
function Get-EventDataValue {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Event,

        [Parameter(Mandatory)]
        [string]$FieldName
    )

    process {
        $sourceEvent = if ($Event.SourceEvent) { $Event.SourceEvent } else { $Event }
        $xml = [xml]$sourceEvent.ToXml()

        # Try EventData (most common)
        $value = ($xml.Event.EventData.Data | Where-Object Name -eq $FieldName).'#text'

        # Try UserData if EventData didn't have it
        if (-not $value -and $xml.Event.UserData) {
            $value = $xml.Event.UserData.SelectSingleNode("//*[local-name()='$FieldName']").'#text'
        }

        $value
    }
}
```

### Get-EventFields (discover available fields)

```powershell
function Get-EventFields {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Event
    )

    process {
        $sourceEvent = if ($Event.SourceEvent) { $Event.SourceEvent } else { $Event }
        $xml = [xml]$sourceEvent.ToXml()

        # EventData structure (most common)
        $xml.Event.EventData.Data | Where-Object { $_.Name } | ForEach-Object {
            [PSCustomObject]@{
                Source = 'EventData'
                Name   = $_.Name
                Value  = $_.'#text'
            }
        }

        # UserData structure (best-effort, may miss deeply nested)
        if ($xml.Event.UserData) {
            $xml.Event.UserData.SelectNodes('//*[text()]') | ForEach-Object {
                [PSCustomObject]@{
                    Source = 'UserData'
                    Name   = $_.LocalName
                    Value  = $_.'#text'
                }
            }
        }
    }
}

# Usage: discover fields for an event type
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1 | Get-EventFields
```

---

## Investigation Playbooks

### Playbook: Unexpected Reboot

**Symptom:** Server rebooted without explanation

```powershell
# Step 1: Find reboot events (last 7 days)
$rebootEvents = Get-EventLogData -LogName System -Id 41,6008,1074,6005,6006 -StartTime (Get-Date).AddDays(-7)

Write-Host "Found $($rebootEvents.Count) reboot-related events"

# Step 2: Timeline view
$rebootEvents | Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, MachineName, MessageShort |
    Format-Table -Wrap

# Event ID reference:
# 41    - Kernel-Power: unexpected restart (no clean shutdown)
# 6008  - EventLog: unexpected shutdown (previous boot wasn't clean)
# 1074  - User32: initiated shutdown/restart (includes who/why)
# 6005  - EventLog: service started (boot marker)
# 6006  - EventLog: service stopped (clean shutdown marker)
```

**Correlation:** Query ±5 minutes around the reboot:

```powershell
$crashTime = $rebootEvents | Where-Object Id -eq 41 |
    Select-Object -First 1 -ExpandProperty TimeCreated

if ($crashTime) {
    Get-EventLogData -LogName System,Application -Level 1,2,3 `
        -StartTime $crashTime.AddMinutes(-5) `
        -EndTime $crashTime.AddMinutes(5) |
        Sort-Object TimeCreated |
        Select-Object TimeCreated, LogName, ProviderName, Id, MessageShort
}
```

---

### Playbook: Service Keeps Dying

**Symptom:** A service crashes or stops unexpectedly

```powershell
# Step 1: Find service crash events
$serviceCrashes = Get-EventLogData -LogName System -Id 7031,7034 -ProviderName 'Service Control Manager'

# Event ID reference:
# 7031 - Service terminated unexpectedly (will attempt recovery)
# 7034 - Service terminated unexpectedly (no recovery action)

# Step 2: Correlate with application crashes
$appCrashes = Get-EventLogData -LogName Application -Id 1000,1001,1002

# Event ID reference:
# 1000 - Application Error (crash with fault details)
# 1001 - Windows Error Reporting (fault bucket info)
# 1002 - Application Hang (not responding)

# Step 3: Combine, correlate by time
$allCrashes = $serviceCrashes + $appCrashes |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, LogName, Id, ProviderName, ProcessId, MessageShort

Write-Host "Found $($serviceCrashes.Count) service crashes, $($appCrashes.Count) app crashes"
$allCrashes | Format-Table -Wrap
```

---

### Playbook: Account Lockouts

**Symptom:** User keeps getting locked out

```powershell
# Step 1: Find lockout events (run on domain controller)
$lockouts = Get-EventLogData -LogName Security -Id 4740 -IncludeSourceEvent

Write-Host "Found $($lockouts.Count) lockout events"

# Step 2: Extract lockout details using XML (not Properties indexes!)
$lockouts | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        LockedUser  = $_ | Get-EventDataValue -FieldName 'TargetUserName'
        LockedOnDC  = $_ | Get-EventDataValue -FieldName 'SubjectDomainName'
        CallerComputer = $_ | Get-EventDataValue -FieldName 'TargetDomainName'
    }
}

# Step 3: Find failed logons for a specific user
$username = "jsmith"  # Change to actual username

$failedLogons = Get-EventLogData -LogName Security -Id 4625 -IncludeSourceEvent |
    Where-Object {
        ($_ | Get-EventDataValue -FieldName 'TargetUserName') -eq $username
    }

Write-Host "Found $($failedLogons.Count) failed logons for $username"

# Step 4: Extract details for each failure
$failedLogons | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        TargetUser  = $_ | Get-EventDataValue -FieldName 'TargetUserName'
        Workstation = $_ | Get-EventDataValue -FieldName 'WorkstationName'
        IpAddress   = $_ | Get-EventDataValue -FieldName 'IpAddress'
        SubStatus   = $_ | Get-EventDataValue -FieldName 'SubStatus'
        LogonType   = $_ | Get-EventDataValue -FieldName 'LogonType'
    }
} | Format-Table

# SubStatus codes:
# 0xC0000064 - User does not exist
# 0xC000006A - Wrong password
# 0xC0000072 - Account disabled
# 0xC0000234 - Account locked out
```

---

### Playbook: RDP Logon Investigation

**Symptom:** Audit who logged in via RDP

```powershell
# Method 1: XPath filter for LogonType 10 (most efficient)
$rdpLogons = Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4624)]]
and
*[EventData[Data[@Name='LogonType']='10']]
"@ -MaxEvents 100 -ErrorAction SilentlyContinue

Write-Host "Found $($rdpLogons.Count) RDP logons"

# Extract details
$rdpLogons | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time        = $_.TimeCreated
        User        = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        Domain      = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
        SourceIP    = ($data | Where-Object Name -eq 'IpAddress').'#text'
        Workstation = ($data | Where-Object Name -eq 'WorkstationName').'#text'
    }
} | Format-Table

# Method 2: Also check TerminalServices log for session details
Get-EventLogData -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' `
    -Id 21,22,23,24,25 -MaxEvents 50 |
    Select-Object TimeCreated, Id, MachineName, MessageShort
# 21 = Session logon succeeded
# 22 = Shell start notification
# 23 = Session logoff succeeded
# 24 = Session disconnected
# 25 = Session reconnected
```

---

### Playbook: Persistence / Suspicious Changes

**Symptom:** Investigate potential unauthorized changes or persistence mechanisms

```powershell
# === NEW SERVICES ===
# Event 7045 in System log (always logged)
$newServices = Get-EventLogData -LogName System -Id 7045 -StartTime (Get-Date).AddDays(-7)

Write-Host "New services installed: $($newServices.Count)"
$newServices | Select-Object TimeCreated, MachineName, MessageShort | Format-Table -Wrap

# Event 4697 in Security (if auditing enabled - often not)
$newServicesAudit = Get-EventLogData -LogName Security -Id 4697 -StartTime (Get-Date).AddDays(-7) -IncludeSourceEvent

$newServicesAudit | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        ServiceName = $_ | Get-EventDataValue -FieldName 'ServiceName'
        ServicePath = $_ | Get-EventDataValue -FieldName 'ServiceFileName'
        AccountUsed = $_ | Get-EventDataValue -FieldName 'SubjectUserName'
    }
}

# === USER ACCOUNT CHANGES ===
$userChanges = Get-EventLogData -LogName Security `
    -Id 4720,4722,4723,4724,4725,4726 `
    -StartTime (Get-Date).AddDays(-7) -IncludeSourceEvent

Write-Host "User account changes: $($userChanges.Count)"

# 4720 = User created
# 4722 = User enabled
# 4723 = Password change attempted
# 4724 = Password reset attempted
# 4725 = User disabled
# 4726 = User deleted

$userChanges | ForEach-Object {
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        EventId    = $_.Id
        TargetUser = $_ | Get-EventDataValue -FieldName 'TargetUserName'
        ByUser     = $_ | Get-EventDataValue -FieldName 'SubjectUserName'
    }
} | Format-Table

# === GROUP MEMBERSHIP CHANGES ===
$groupChanges = Get-EventLogData -LogName Security `
    -Id 4728,4729,4732,4733,4756,4757 `
    -StartTime (Get-Date).AddDays(-7) -IncludeSourceEvent

Write-Host "Group membership changes: $($groupChanges.Count)"

# 4728/4729 = Added/removed from global group
# 4732/4733 = Added/removed from local group
# 4756/4757 = Added/removed from universal group

$groupChanges | ForEach-Object {
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Action     = if ($_.Id -in 4728,4732,4756) { 'Added' } else { 'Removed' }
        Member     = $_ | Get-EventDataValue -FieldName 'MemberName'
        Group      = $_ | Get-EventDataValue -FieldName 'TargetUserName'
        ByUser     = $_ | Get-EventDataValue -FieldName 'SubjectUserName'
    }
} | Format-Table

# === SCHEDULED TASKS ===
# TaskScheduler Operational log (if enabled)
$taskLog = 'Microsoft-Windows-TaskScheduler/Operational'
$taskEvents = Get-EventLogData -LogName $taskLog -Id 106,140,141,200,201 `
    -StartTime (Get-Date).AddDays(-7) -MaxEvents 200

Write-Host "Scheduled task events: $($taskEvents.Count)"
# 106 = Task registered
# 140 = Task updated
# 141 = Task deleted
# 200 = Task started
# 201 = Task completed

$taskEvents | Where-Object Id -in 106,140,141 |
    Select-Object TimeCreated, Id, MessageShort | Format-Table -Wrap
```

---

## Offline Analysis (.evtx Files)

### Export Logs

```powershell
# Export using wevtutil (fast, preserves everything)
$exportPath = "C:\temp\evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $exportPath -Force | Out-Null

wevtutil epl System "$exportPath\System.evtx" /ow:true
wevtutil epl Application "$exportPath\Application.evtx" /ow:true
wevtutil epl Security "$exportPath\Security.evtx" /ow:true

Write-Host "Exported to: $exportPath"
```

### Query Offline Files

```powershell
# Use the wrapper with -Path parameter
$events = Get-EventLogData -LogName System -Path "C:\temp\evidence\System.evtx" `
    -Level 1,2 -StartTime (Get-Date).AddDays(-7)

Write-Host "Found $($events.Count) events in offline log"
$events | Select-Object TimeCreated, Id, MachineName, MessageShort | Format-Table
```

### When to Use Offline Export

- **Evidence preservation:** Export BEFORE investigation changes anything
- **Remote access issues:** Export locally, transfer, analyze at your desk
- **Sharing with others:** .evtx files are portable and complete
- **Historical analysis:** Archived logs from decommissioned systems
- **Large log analysis:** Export, then query without impacting production

---

## Remote Query Patterns

### Pattern 1: RPC Direct (Get-WinEvent -ComputerName)

Best when: Already have admin rights, ports 135+dynamic open, same domain

```powershell
# Simple case - current credentials work
Get-EventLogData -LogName System -ComputerName SERVER01 -Id 41,6008 -MaxEvents 50

# Note: -Credential often doesn't work as expected with Get-WinEvent
# If you need different credentials, use Pattern 2
```

### Pattern 2: WinRM with Invoke-Command (Recommended)

Best when: Need explicit credentials, WinRM is configured, port 5985/5986 open

```powershell
$cred = Get-Credential

# Run the query remotely, return results
$results = Invoke-Command -ComputerName SERVER01 -Credential $cred -ScriptBlock {
    Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 41,6008
        StartTime = (Get-Date).AddDays(-7)
    } -MaxEvents 50 | Select-Object RecordId, TimeCreated, Id,
        @{N='Message'; E={($_.Message -split "`n")[0]}}
}

$results | Format-Table
```

### Pattern 3: Export and Transfer (Most Reliable)

Best when: Connectivity is flaky, need evidence preservation, dealing with Security log

```powershell
# On the remote server (via RDP, or run as scheduled task)
wevtutil epl Security C:\temp\Security.evtx /ow:true

# Transfer the file (robocopy, SMB, whatever works)
# Then analyze locally
Get-EventLogData -LogName Security -Path "\\SERVER01\c$\temp\Security.evtx" -Id 4625 -MaxEvents 100
```

### Connectivity Troubleshooting

```powershell
# Test RPC (port 135)
Test-NetConnection -ComputerName SERVER01 -Port 135

# Test WinRM (port 5985)
Test-NetConnection -ComputerName SERVER01 -Port 5985
Test-WSMan -ComputerName SERVER01

# Common issues:
# - "RPC server unavailable" = firewall blocking 135 or dynamic ports
# - "Access denied" = not admin, or Security log requires Event Log Readers
# - "WinRM cannot process" = WinRM not enabled on target
```

### Security Log Access Requirements

Local admin is often **not enough** for Security log:

- Must be in **Event Log Readers** group, OR
- Must have **SeSecurityPrivilege**, OR
- Must be **Domain Admin** (for DCs)

Check your access:
```powershell
whoami /groups | Select-String "Event Log Readers"
whoami /priv | Select-String "SeSecurityPrivilege"
```

---

## Provider and Channel Gotchas

### Many Operational Logs Are Disabled by Default

```powershell
# Check if a log is enabled
$log = Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue
if ($log) {
    Write-Host "Enabled: $($log.IsEnabled), Records: $($log.RecordCount)"
} else {
    Write-Host "Log not found or inaccessible"
}

# Common disabled-by-default logs you might need:
# - Microsoft-Windows-DNS-Client/Operational
# - Microsoft-Windows-CAPI2/Operational
# - Microsoft-Windows-PrintService/Operational
```

### Enabling a Log (Requires Approval)

```powershell
# WARNING: This changes system configuration. Confirm with user first.
wevtutil sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true

# Better: Check what's enabled across the system
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Where-Object { $_.IsEnabled -eq $false -and $_.RecordCount -gt 0 } |
    Select-Object LogName, RecordCount, IsEnabled
```

### Retention and Size Limits

```powershell
# Check log size and retention
Get-WinEvent -ListLog System,Security,Application |
    Select-Object LogName, MaximumSizeInBytes,
        @{N='MaxSizeMB'; E={[math]::Round($_.MaximumSizeInBytes/1MB, 2)}},
        RecordCount, FileSize, LogMode

# LogMode values:
# - Circular: Old events overwritten (default)
# - Retain: Stop when full
# - AutoBackup: Archive and continue
```

### High-Value Operational Logs

| Log | Use Case | Default |
|-----|----------|---------|
| `Microsoft-Windows-PowerShell/Operational` | Script execution, command history | Enabled |
| `Microsoft-Windows-TaskScheduler/Operational` | Scheduled task runs | Varies |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | RDP session events | Enabled |
| `Microsoft-Windows-Windows Defender/Operational` | AV detections | Enabled |
| `Microsoft-Windows-Sysmon/Operational` | Process/network monitoring | Requires Sysmon |
| `Microsoft-Windows-DNS-Client/Operational` | DNS lookups | Disabled |
| `Microsoft-Windows-CAPI2/Operational` | Certificate operations | Disabled |

---

## Correlation Patterns

### Time Window Correlation

```powershell
function Get-CorrelatedEvents {
    param(
        [Parameter(Mandatory)]
        [datetime]$AnchorTime,

        [int]$WindowMinutes = 5,

        [string[]]$LogName = @('System', 'Application', 'Security'),

        [string]$ComputerName,

        [string]$Path
    )

    $params = @{
        LogName   = $LogName
        StartTime = $AnchorTime.AddMinutes(-$WindowMinutes)
        EndTime   = $AnchorTime.AddMinutes($WindowMinutes)
        MaxEvents = 500
    }

    if ($ComputerName) { $params['ComputerName'] = $ComputerName }
    if ($Path) { $params['Path'] = $Path }

    Get-EventLogData @params |
        Sort-Object TimeCreated |
        Select-Object TimeCreated, LogName, ProviderName, Id, ProcessId, MessageShort
}

# Usage: what happened around 10:32?
Get-CorrelatedEvents -AnchorTime '2026-01-16 10:32:00' -WindowMinutes 5
```

### Top Offenders Summary

```powershell
function Get-EventSummary {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Events
    )

    begin { $allEvents = @() }
    process { $allEvents += $Events }
    end {
        [PSCustomObject]@{
            TotalEvents = $allEvents.Count
            TimeRange   = "{0} to {1}" -f
                ($allEvents.TimeCreated | Measure-Object -Minimum).Minimum,
                ($allEvents.TimeCreated | Measure-Object -Maximum).Maximum
            ByLevel     = $allEvents | Group-Object LevelName |
                Sort-Object Count -Descending |
                Select-Object Name, Count
            TopProviders = $allEvents | Group-Object ProviderName |
                Sort-Object Count -Descending |
                Select-Object Name, Count -First 10
            TopEventIds = $allEvents | Group-Object Id |
                Sort-Object Count -Descending |
                Select-Object @{N='EventId'; E={$_.Name}}, Count -First 10
        }
    }
}

# Usage
Get-EventLogData -LogName System,Application -Level 1,2 -StartTime (Get-Date).AddDays(-7) |
    Get-EventSummary
```

---

## Exporting Events

### Export Behavior Rules

**CRITICAL: When exporting events, run ONE command and report the result. Do NOT:**

- Check if the file exists after export
- Count lines in the exported file
- Get file size or properties
- Read the file back to verify contents
- Run multiple verification commands

**DO:**

- Run a single export command that outputs the count
- Report "Exported X events to [path]" and stop

### CSV Export (Single Command)

```powershell
# Export Application log errors to CSV - outputs count automatically
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Export-Csv -Path 'C:\Temp\AppErrors.csv' -NoTypeInformation -PassThru | Measure-Object | ForEach-Object { "Exported $($_.Count) events to C:\Temp\AppErrors.csv" }
```

### JSON Export (Single Command)

```powershell
# Export to JSON with count
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | ConvertTo-Json | Out-File 'C:\Temp\SystemErrors.json'; "Exported to C:\Temp\SystemErrors.json"
```

### EVTX Export (Native Format - Fastest)

```powershell
# Export native .evtx format - best for archiving and forensics
wevtutil epl Application 'C:\Temp\Application.evtx' /ow:true; "Exported Application log to C:\Temp\Application.evtx"

# Export with query filter
wevtutil epl System 'C:\Temp\System_Errors.evtx' /q:"*[System[(Level=1 or Level=2)]]" /ow:true; "Exported filtered System log"
```

### Common Export Patterns (Copy-Paste Ready)

```powershell
# Application errors last 30 days to CSV
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Export-Csv 'C:\Temp\Application_Events.csv' -NoTypeInformation; "Export complete"

# System errors last 7 days to CSV
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message | Export-Csv 'C:\Temp\System_Events.csv' -NoTypeInformation; "Export complete"

# Security events last 24 hours to CSV (requires admin)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 5000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Export-Csv 'C:\Temp\Security_Events.csv' -NoTypeInformation; "Export complete"

# All logs native export (fastest for large exports)
wevtutil epl System 'C:\Temp\System.evtx' /ow:true; wevtutil epl Application 'C:\Temp\Application.evtx' /ow:true; wevtutil epl Security 'C:\Temp\Security.evtx' /ow:true; "Exported all logs to C:\Temp"
```

---

## High-Value Event IDs Reference

### Security Events

| ID | Description | Notes |
|----|-------------|-------|
| 4624 | Successful logon | Check LogonType field |
| 4625 | Failed logon | SubStatus shows reason |
| 4634 | Logoff | |
| 4648 | Explicit credential logon | RunAs, scheduled tasks |
| 4672 | Special privileges assigned | Admin logon indicator |
| 4697 | Service installed | Requires audit policy |
| 4720 | User account created | |
| 4722 | User account enabled | |
| 4723 | Password change attempted | |
| 4724 | Password reset attempted | |
| 4725 | User account disabled | |
| 4726 | User account deleted | |
| 4728 | User added to global group | |
| 4729 | User removed from global group | |
| 4732 | User added to local group | |
| 4733 | User removed from local group | |
| 4740 | Account locked out | |
| 4756 | User added to universal group | |
| 4757 | User removed from universal group | |

### Logon Types (for 4624/4625)

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, mapped drive |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials |

### System Events

| ID | Provider | Description |
|----|----------|-------------|
| 41 | Kernel-Power | Unexpected restart |
| 1074 | User32 | Initiated shutdown |
| 6005 | EventLog | Service started (boot) |
| 6006 | EventLog | Service stopped (shutdown) |
| 6008 | EventLog | Unexpected shutdown |
| 6013 | EventLog | Uptime |
| 7031 | SCM | Service crashed (recovery pending) |
| 7034 | SCM | Service crashed (no recovery) |
| 7036 | SCM | Service state change |
| 7040 | SCM | Service start type changed |
| 7045 | SCM | New service installed |

### Application Events

| ID | Provider | Description |
|----|----------|-------------|
| 1000 | Application Error | Process crash |
| 1001 | WER | Fault bucket details |
| 1002 | Application Hang | Not responding |

---

## XPath Query Patterns

### Filter by EventData Fields

```powershell
# RDP logons (LogonType 10)
Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4624)]]
and
*[EventData[Data[@Name='LogonType']='10']]
"@ -MaxEvents 50

# Failed logons for specific user
Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4625)]]
and
*[EventData[Data[@Name='TargetUserName']='jsmith']]
"@ -MaxEvents 100

# Time-based (UTC format)
$startUtc = (Get-Date).AddHours(-1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
Get-WinEvent -LogName System -FilterXPath "*[System[TimeCreated[@SystemTime>='$startUtc']]]" -MaxEvents 100
```

### When to Use XPath vs FilterHashtable

| Use FilterHashtable | Use XPath |
|---------------------|-----------|
| Filter by LogName, Id, Level, Provider | Filter by EventData field values |
| Simple time ranges | LogonType, Username, IP filtering |
| Multiple Event IDs | Complex nested conditions |
| Performance critical | Need surgical precision |

---

## Performance Tips

1. **Always use `-FilterHashtable` or `-FilterXPath`** - 10-100x faster than `Where-Object`

2. **Always set `-MaxEvents`** - even 500-1000 prevents runaway queries

3. **Always set time boundaries** - `StartTime` prevents full log scans

4. **Query logs individually when possible** - multiple logs in one call can be slower

5. **Keep objects in pipeline** - don't `Format-*` until final output

6. **Use `-ErrorAction Stop` with try/catch** - controlled error handling, not silent failures

7. **Export large logs for analysis** - query .evtx files instead of hitting production repeatedly

```powershell
# Good: filtered, bounded, objects in pipeline
Get-EventLogData -LogName System -Level 1,2 -StartTime (Get-Date).AddDays(-1) -MaxEvents 500 |
    Where-Object ProcessId -ne 0 |
    Select-Object TimeCreated, ProviderName, Id, ProcessId, MessageShort

# Bad: pulls everything, filters in memory
Get-WinEvent -LogName System |
    Where-Object { $_.Level -le 2 } |
    Format-Table
```
