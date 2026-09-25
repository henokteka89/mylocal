<#
.SYNOPSIS
    Holistic Always On AG diagnostic: storage + OS + network + cluster + Azure + SQL,
    merged into ONE findings list, ONE cross-node timeline and ONE verdict, each with interpretation.

.DESCRIPTION
    Layer 1  SQL      runs AG_Diag_SQL.sql on every replica (in parallel, same sample window)
    Layer 2  OS       live counters on every node (disk latency/queue, CPU, memory, TCP retransmits, NIC)
                      + volumes, System log storage/NIC/reboot events, top CPU processes, time sync
    Layer 3  Cluster  node/network state, heartbeat thresholds, AG resource LeaseTimeout /
                      HealthCheckTimeout / FCL, failover threshold, FailoverClustering events,
                      cluster log scan (lease, health-check, heartbeat, node removal, failover)
    Layer 4  Azure    VM size + scheduled (platform) events from IMDS when running on Azure
    Output   Findings.csv, Timeline.csv, AGDiag_Report.html (+ raw CSVs) in -OutDir

    Live checks (counters, SQL deltas, queues) describe NOW. Events, logs and XE describe the
    window (-HoursBack or -StartTime/-EndTime). Use a window for post-incident analysis.

.REQUIREMENTS
    Run as a domain account that is local admin on every node and sysadmin on every instance.
    WinRM (Invoke-Command) and remote performance counters to each node.
    SqlServer PowerShell module on the machine running this script (for Invoke-Sqlcmd).
    FailoverClusters module on the nodes (present on cluster nodes).
    Windows PowerShell 5.1 or PowerShell 7. English counter names.

.EXAMPLE
    # Live: something is lagging right now
    .\Invoke-AGDiag.ps1 -Replicas @{Computer='SQLPRI01';Instance='SQLPRI01'}, @{Computer='SQLSEC01';Instance='SQLSEC01'}

.EXAMPLE
    # Post-incident: automatic failover happened around 02:05 last night
    .\Invoke-AGDiag.ps1 -Replicas @{Computer='SQLPRI01';Instance='SQLPRI01'}, @{Computer='SQLSEC01';Instance='SQLSEC01\PROD'} `
        -StartTime '2026-09-23 01:30' -EndTime '2026-09-23 02:30'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [hashtable[]] $Replicas,       # @{Computer='host';Instance='host\inst'}
    [int]      $HoursBack     = 24,
    [datetime] $StartTime,
    [datetime] $EndTime,
    [int]      $SampleSeconds = 30,
    [string]   $SqlScript     = (Join-Path $PSScriptRoot 'AG_Diag_SQL.sql'),
    [string]   $OutDir        = ("C:\temp\AGDiag_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmm')),
    [switch]   $SkipClusterLog,
    [switch]   $SkipSql
)

$ErrorActionPreference = 'Continue'
if (-not $StartTime) { $StartTime = (Get-Date).AddHours(-$HoursBack) }
if (-not $EndTime)   { $EndTime   = Get-Date }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Get-ShortName([string]$n) { if (-not $n) { return '' }; return ($n.Split('\')[0].Split('.')[0]).ToUpper() }

$Computers = @($Replicas | ForEach-Object { $_.Computer } | Select-Object -Unique)
$InstToNode = @{}
foreach ($r in $Replicas) { $InstToNode[$r.Instance] = Get-ShortName $r.Computer }

$Findings = New-Object System.Collections.Generic.List[object]
$Timeline = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param($Node, $Layer, $Severity, $Area, $Check, $Value, $Threshold, $Interpretation, $NextStep, $Tag)
    $Findings.Add([pscustomobject]@{
        Node = $Node; Layer = $Layer; Severity = $Severity; Area = $Area; Check = $Check; Value = $Value
        Threshold = $Threshold; Interpretation = $Interpretation; NextStep = $NextStep; Tag = $Tag })
}
function Add-Event {
    param([datetime]$Time, $Node, $Source, $Event, $Severity, $Tag, $Detail)
    $Timeline.Add([pscustomobject]@{
        Time = $Time; Node = $Node; Source = $Source; Event = $Event; Severity = $Severity; Tag = $Tag; Detail = $Detail })
}
function ConvertTo-LocalTime($s) {
    if (-not $s) { return $null }
    try { return ([datetimeoffset]::Parse([string]$s, [Globalization.CultureInfo]::InvariantCulture)).LocalDateTime } catch { return $null }
}

Write-Host "AG diagnostic  window $StartTime -> $EndTime  nodes: $($Computers -join ', ')" -ForegroundColor Cyan

#region ---------------------------------------------------------------- 1. SQL layer (background, overlaps OS sample)
$sqlJobs = @()
if (-not $SkipSql) {
    if (-not (Test-Path $SqlScript)) { throw "SQL script not found: $SqlScript (put AG_Diag_SQL.sql next to this script or pass -SqlScript)" }
    $hb = [math]::Max(1, [math]::Ceiling(((Get-Date) - $StartTime).TotalHours))
    $sqlText = (Get-Content -Path $SqlScript -Raw) `
        -replace 'DECLARE @HoursBack\s+int\s*=\s*\d+;', "DECLARE @HoursBack int = $hb;" `
        -replace 'DECLARE @SampleSec\s+int\s*=\s*\d+;', "DECLARE @SampleSec int = $SampleSeconds;"
    foreach ($r in $Replicas) {
        Write-Host "  SQL collector started on $($r.Instance)"
        $sqlJobs += Start-Job -Name ("sql_" + $r.Instance) -ArgumentList $r.Instance, $sqlText -ScriptBlock {
            param($inst, $q)
            Import-Module SqlServer -ErrorAction Stop
            $p = @{ ServerInstance = $inst; Query = $q; QueryTimeout = 1200; OutputAs = 'DataSet'; ErrorAction = 'Stop' }
            if ((Get-Command Invoke-Sqlcmd).Parameters.ContainsKey('TrustServerCertificate')) { $p['TrustServerCertificate'] = $true }
            $ds = Invoke-Sqlcmd @p
            $ex = 'ItemArray', 'Table', 'RowError', 'RowState', 'HasErrors'
            [pscustomobject]@{
                Instance = $inst
                Findings = @($ds.Tables[0] | Select-Object * -ExcludeProperty $ex)
                Timeline = @($ds.Tables[1] | Select-Object * -ExcludeProperty $ex)
            }
        }
    }
}
#endregion

#region ---------------------------------------------------------------- 2. OS live counters (all nodes at once)
Write-Host "  Sampling OS counters for $SampleSeconds s ..."
$ctrs = @(
    '\LogicalDisk(*)\Avg. Disk sec/Read', '\LogicalDisk(*)\Avg. Disk sec/Write',
    '\LogicalDisk(*)\Current Disk Queue Length', '\LogicalDisk(*)\Disk Transfers/sec', '\LogicalDisk(*)\Disk Bytes/sec',
    '\Processor(_Total)\% Processor Time', '\Memory\Available MBytes', '\Memory\Pages/sec',
    '\TCPv4\Segments Sent/sec', '\TCPv4\Segments Retransmitted/sec',
    '\Network Interface(*)\Bytes Total/sec', '\Network Interface(*)\Current Bandwidth')
$interval = 2
$n = [math]::Max(3, [int]($SampleSeconds / $interval))
$samples = Get-Counter -ComputerName $Computers -Counter $ctrs -SampleInterval $interval -MaxSamples $n -ErrorAction SilentlyContinue

$ctrRows = foreach ($s in $samples) {
    foreach ($cs in $s.CounterSamples) {
        $parts = $cs.Path.TrimStart('\').Split('\')
        [pscustomobject]@{
            Node = Get-ShortName $parts[0]; Object = ($parts[1] -replace '\(.*$', ''); Instance = $cs.InstanceName
            Counter = $parts[-1]; Value = $cs.CookedValue; Time = $s.Timestamp }
    }
}
if (-not $samples) {
    Add-Finding 'ALL' 'Collector' 'WARNING' 'Collection' 'remote performance counters' 'no samples returned' '' `
        'Live OS counters could not be read (Remote Registry / Performance Log Users permission / firewall). Disk latency and network live checks are missing.' `
        'Run Get-Counter locally on each node, or workbook Step 5d / 4d.' 'COLLECT_FAIL'
}
$ctrRows | Export-Csv (Join-Path $OutDir 'raw_os_counters.csv') -NoTypeInformation
$ctrAgg = $ctrRows | Group-Object Node, Object, Instance, Counter | ForEach-Object {
    $m = $_.Group | Measure-Object Value -Average -Maximum
    $f = $_.Group[0]
    [pscustomobject]@{ Node = $f.Node; Object = $f.Object; Instance = $f.Instance; Counter = $f.Counter; Avg = $m.Average; Max = $m.Maximum }
}

foreach ($node in ($ctrAgg | Select-Object -ExpandProperty Node -Unique)) {
    $c = @($ctrAgg | Where-Object Node -eq $node)

    # Disk latency and queue per volume
    $vols = $c | Where-Object { $_.Object -eq 'logicaldisk' -and $_.Instance -ne '_total' -and $_.Instance -notlike 'harddiskvolume*' } |
            Select-Object -ExpandProperty Instance -Unique
    foreach ($v in $vols) {
        $w  = $c | Where-Object { $_.Instance -eq $v -and $_.Counter -eq 'avg. disk sec/write' }
        $rd = $c | Where-Object { $_.Instance -eq $v -and $_.Counter -eq 'avg. disk sec/read' }
        $q  = $c | Where-Object { $_.Instance -eq $v -and $_.Counter -eq 'current disk queue length' }
        $io = $c | Where-Object { $_.Instance -eq $v -and $_.Counter -eq 'disk transfers/sec' }
        $wAvg = [math]::Round(1000 * $w.Avg, 1);  $wMax = [math]::Round(1000 * $w.Max, 1)
        $rAvg = [math]::Round(1000 * $rd.Avg, 1); $rMax = [math]::Round(1000 * $rd.Max, 1)
        $worstAvg = [math]::Max($wAvg, $rAvg); $worstMax = [math]::Max($wMax, $rMax)
        $sev = if ($worstAvg -gt 25 -or $worstMax -gt 200) { 'CRITICAL' } elseif ($worstAvg -gt 10 -or $worstMax -gt 50 -or $q.Avg -gt 10) { 'WARNING' } else { 'OK' }
        $interp = switch ($sev) {
            'CRITICAL' { "Volume $v is stalling (avg $worstAvg ms, spikes $worstMax ms). If it holds SQL log files, every commit / harden waits on it; on the secondary this throttles the whole AG. Multi-second spikes freeze threads enough to miss lease renewals and health checks." }
            'WARNING'  { "Volume $v latency or queue is elevated. A long queue with modest IOPS usually means the disk or VM has hit its IOPS/throughput cap (throttling) or the storage path is slow." }
            default    { "Volume $v latency normal in the sample." }
        }
        Add-Finding $node 'OS' $sev 'Disk latency (live)' "$v read/write ms avg | max, queue avg, IOPS" `
            ("read {0} | {1}  write {2} | {3}  queue {4}  iops {5}" -f $rAvg, $rMax, $wAvg, $wMax, [math]::Round($q.Avg, 1), [math]::Round($io.Avg, 0)) `
            'avg >10 ms warn, >25 crit; spike >200 ms crit; queue >10 warn' $interp `
            $(if ($sev -ne 'OK') { 'Match the volume to SQL LOG/DATA rows; check VM/disk IOPS and bandwidth caps (Azure: Data Disk / VM Uncached IOPS & Bandwidth Consumed Percentage); storage team or provider with timestamps.' }) `
            $(if ($sev -ne 'OK') { 'OS_DISK_LATENCY' })
    }

    # CPU / memory
    $cpu = $c | Where-Object { $_.Object -eq 'processor' }
    if ($cpu) {
        $sev = if ($cpu.Max -ge 95) { 'CRITICAL' } elseif ($cpu.Avg -ge 80) { 'WARNING' } else { 'OK' }
        Add-Finding $node 'OS' $sev 'CPU (live)' 'Processor % avg | max' ("{0} | {1}" -f [math]::Round($cpu.Avg, 0), [math]::Round($cpu.Max, 0)) 'avg <80, max <95' `
            $(if ($sev -ne 'OK') { 'CPU saturated: redo, log harden, lease renewal and sp_server_diagnostics compete for CPU. Pegged CPU is a documented lease-timeout cause.' } else { 'CPU normal.' }) `
            $(if ($sev -ne 'OK') { 'See Top processes row; SQL CPU rows.' }) $(if ($sev -ne 'OK') { 'OS_CPU' })
    }
    $mem = $c | Where-Object { $_.Counter -eq 'available mbytes' }
    $pg  = $c | Where-Object { $_.Counter -eq 'pages/sec' }
    if ($mem) {
        $sev = if ($mem.Avg -lt 500) { 'CRITICAL' } elseif ($mem.Avg -lt 1024) { 'WARNING' } else { 'OK' }
        Add-Finding $node 'OS' $sev 'Memory (live)' 'Available MB avg | Pages/sec avg' ("{0} | {1}" -f [math]::Round($mem.Avg, 0), [math]::Round($pg.Avg, 0)) 'available >1024 MB' `
            $(if ($sev -ne 'OK') { 'OS memory pressure: working-set paging of SQL Server is a documented lease-timeout cause. Check max server memory and Lock Pages in Memory.' } else { 'OS memory OK.' }) `
            $null $(if ($sev -ne 'OK') { 'OS_MEMORY_LOW' })
    }

    # TCP retransmits
    $sent = $c | Where-Object { $_.Counter -eq 'segments sent/sec' }
    $retr = $c | Where-Object { $_.Counter -eq 'segments retransmitted/sec' }
    if ($sent -and $sent.Avg -gt 0) {
        $pct = [math]::Round(100 * $retr.Avg / $sent.Avg, 2)
        $sev = if ($pct -gt 3) { 'CRITICAL' } elseif ($pct -gt 1) { 'WARNING' } else { 'OK' }
        Add-Finding $node 'Network' $sev 'TCP retransmits (live)' 'retransmitted % of segments sent' "$pct %" 'warn >1 %, crit >3 %' `
            $(if ($sev -ne 'OK') { 'Packet loss on this node. AG log blocks and cluster heartbeats (UDP 3343) suffer the same loss: expect resent messages, 35206 timeouts, flow control and send-queue growth.' } else { 'No meaningful packet loss.' }) `
            $(if ($sev -ne 'OK') { 'NIC driver/firmware, teaming, MTU, firewall/IPS inspection on port 5022 and 3343.' }) $(if ($sev -ne 'OK') { 'NET_RETRANS' })
    }

    # NIC utilisation
    foreach ($nic in ($c | Where-Object { $_.Object -eq 'network interface' -and $_.Counter -eq 'bytes total/sec' })) {
        $bw = $c | Where-Object { $_.Object -eq 'network interface' -and $_.Instance -eq $nic.Instance -and $_.Counter -eq 'current bandwidth' }
        if ($bw -and $bw.Avg -gt 0) {
            $util = [math]::Round(100 * 8 * $nic.Max / $bw.Avg, 1)
            if ($util -gt 70) {
                Add-Finding $node 'Network' 'WARNING' 'NIC utilisation (live)' $nic.Instance "$util % peak" '<70 %' `
                    'NIC near line rate: AG log stream competes with backups, reports or copies on the same NIC.' 'Separate/dedicated NIC or schedule heavy transfers away.' 'NET_SATURATED'
            }
        }
    }
}
#endregion

#region ---------------------------------------------------------------- 3. Per-node collection (volumes, events, cluster, Azure)
$clusterLogMinutes = [int][math]::Ceiling(((Get-Date) - $StartTime).TotalMinutes) + 5
Write-Host "  Collecting OS/cluster data from nodes (cluster log generation can take a few minutes) ..."

$nodeCollector = {
    param([datetime]$Start, [datetime]$End, [int]$ClusterLogMinutes, [bool]$SkipClusterLog)
    $ErrorActionPreference = 'SilentlyContinue'
    function T($d) { if ($d) { return ([datetime]$d).ToString('o') } }
    function Msg($m) { if ($m) { return (($m -replace '\s+', ' ').Substring(0, [math]::Min(350, ($m -replace '\s+', ' ').Length))) } }

    $o = [ordered]@{ Computer = $env:COMPUTERNAME; NowUtc = [datetime]::UtcNow.ToString('o') }

    $os = Get-CimInstance Win32_OperatingSystem
    $o.LastBoot   = T $os.LastBootUpTime
    $o.TotalMemMB = [math]::Round($os.TotalVisibleMemorySize / 1024)
    $o.Volumes    = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.Capacity -gt 0 } |
                      Select-Object Name, Label, @{n = 'CapacityGB'; e = { [math]::Round($_.Capacity / 1GB, 1) } },
                                                 @{n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 1) } })

    $cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    $pc = Get-Counter '\Process(*)\% Processor Time' -SampleInterval 2 -MaxSamples 2
    if ($pc) {
        $o.TopProcesses = @(@($pc)[-1].CounterSamples | Where-Object { $_.InstanceName -notin '_total', 'idle' } |
            Sort-Object CookedValue -Descending | Select-Object -First 6 |
            ForEach-Object { '{0} {1}%' -f $_.InstanceName, [math]::Round($_.CookedValue / $cores, 1) })
    }

    # System log: storage, NIC, reboot, time events
    $rx = '(?i)^(disk|ntfs|microsoft-windows-ntfs|storvsc|stornvme|storahci|storport|microsoft-windows-storport|mpio|microsoft-windows-mpio|iscsiprt|msiscsi|volmgr|volsnap|lsi_sas\d*|vhdmp|nvme\w*|netvsc|mlx\w*|e1\w*|vmxnet\w*|tcpip|microsoft-windows-tcpip|ndis|microsoft-windows-time-service|eventlog|microsoft-windows-kernel-power)$'
    $o.SystemEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Start; EndTime = $End; Level = 1, 2, 3 } -MaxEvents 5000 |
        Where-Object { $_.ProviderName -match $rx } | Select-Object -First 1500 |
        ForEach-Object { [pscustomobject]@{ Time = T $_.TimeCreated; Provider = $_.ProviderName; Id = $_.Id; Level = $_.Level; Message = Msg $_.Message } })

    $o.ClusterEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-FailoverClustering'; StartTime = $Start; EndTime = $End } -MaxEvents 5000 |
        Where-Object { $_.Level -le 3 -or $_.Id -in 1641, 1201 } | Select-Object -First 1000 |
        ForEach-Object { [pscustomobject]@{ Time = T $_.TimeCreated; Id = $_.Id; Level = $_.Level; Message = Msg $_.Message } })

    # SQL messages in the Application log (fallback when the SQL layer cannot connect)
    $o.SqlAppEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $Start; EndTime = $End;
            Id = 833, 1480, 19406, 19407, 19419, 19421, 19422, 35201, 35206, 35264, 9002, 1105, 823, 824 } -MaxEvents 2000 |
        Where-Object { $_.ProviderName -like 'MSSQL*' } | Select-Object -First 500 |
        ForEach-Object { [pscustomobject]@{ Time = T $_.TimeCreated; Id = $_.Id; Provider = $_.ProviderName; Message = Msg $_.Message } })

    $o.NetStats = @(Get-NetAdapterStatistics | Select-Object Name, ReceivedDiscardedPackets, ReceivedPacketErrors, OutboundDiscardedPackets, OutboundPacketErrors)
    $o.W32tm    = ((w32tm /query /status 2>&1) | Out-String).Trim()

    # Azure IMDS (only answers on Azure VMs)
    try {
        $h = @{ Metadata = 'true' }
        $o.Azure = Invoke-RestMethod -Headers $h -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 3 -ErrorAction Stop |
                   Select-Object vmSize, location, zone, name
        $se = Invoke-RestMethod -Headers $h -Uri 'http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01' -TimeoutSec 5 -ErrorAction Stop
        $o.AzureScheduledEvents = @($se.Events | Select-Object EventId, EventType, EventStatus, NotBefore, Description)
    } catch { }

    # Cluster
    if (Get-Module -ListAvailable -Name FailoverClusters) {
        Import-Module FailoverClusters
        $cl = Get-Cluster
        if ($cl) {
            $o.Cluster = $cl | Select-Object Name, SameSubnetDelay, SameSubnetThreshold, CrossSubnetDelay, CrossSubnetThreshold
            $o.ClusterNodes    = @(Get-ClusterNode | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = "$($_.State)" } })
            $o.ClusterNetworks = @(Get-ClusterNetwork | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = "$($_.State)"; Role = "$($_.Role)" } })
            $qu = Get-ClusterQuorum
            $o.Quorum = [pscustomobject]@{ Type = "$($qu.QuorumType)"; Resource = "$($qu.QuorumResource)" }
            $o.AgResources = @(Get-ClusterResource | Where-Object { "$($_.ResourceType)" -eq 'SQL Server Availability Group' } | ForEach-Object {
                $res = $_; $pp = @{}
                $res | Get-ClusterParameter | ForEach-Object { $pp[$_.Name] = $_.Value }
                $grp = Get-ClusterGroup -Name ([string]$res.OwnerGroup)
                [pscustomobject]@{ Name = $res.Name; Owner = "$($res.OwnerNode)"; State = "$($res.State)"
                    LeaseTimeout = $pp['LeaseTimeout']; HealthCheckTimeout = $pp['HealthCheckTimeout']; FailureConditionLevel = $pp['FailureConditionLevel']
                    FailoverThreshold = $grp.FailoverThreshold; FailoverPeriod = $grp.FailoverPeriod }
            })

            if (-not $SkipClusterLog) {
                $dest = Join-Path $env:TEMP 'agdiag_clusterlog'
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                $file = @(Get-ClusterLog -Node $env:COMPUTERNAME -Destination $dest -TimeSpan $ClusterLogMinutes -UseLocalTime)[0].FullName
                $o.ClusterLogFile = $file
                $pats = [ordered]@{
                    'LEASE'           = '(?i)hadrag.*lease'
                    'HEALTH_TIMEOUT'  = '(?i)hadrag.*(heartbeat is lost|health check failed|not healthy with given)'
                    'HADRAG_ERR'      = '(?i)\sERR\s+.*hadrag'
                    'NODE_REMOVED'    = '(?i)(removed from the active failover cluster membership|\[RGP\].*(evict|prun|dead))'
                    'NET_HEARTBEAT'   = '(?i)\[(NETFT|CHANNEL|TM|IM|NODE)[^\]]*\].*(lost|unreachable|missed|timed out|timeout|down)'
                    'FAILOVER_ACTION' = '(?i)\[RCM\].*(failover|move of group|failed)'
                }
                $pre = '(?i)hadrag|\[RGP\]|\[NETFT|\[CHANNEL|\[TM\]|\[IM\]|\[NODE\]|\[RCM\]|membership'
                $hits = New-Object System.Collections.Generic.List[object]
                $counts = @{}
                if ($file -and (Test-Path $file)) {
                    foreach ($mi in (Select-String -Path $file -Pattern $pre)) {
                        $line = $mi.Line
                        foreach ($k in $pats.Keys) {
                            if ($line -match $pats[$k]) {
                                if ($line -match '::(\d{4}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)\s+(.*)$') {
                                    $t = [datetime]::ParseExact($matches[1], 'yyyy/MM/dd-HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
                                    if ($t -ge $Start -and $t -le $End) {
                                        if (-not $counts.ContainsKey($k)) { $counts[$k] = 0 }
                                        $counts[$k]++
                                        if ($counts[$k] -le 150) {
                                            $hits.Add([pscustomobject]@{ Time = T $t; Level = $matches[2]; Tag = $k; Line = Msg $matches[3] })
                                        }
                                    }
                                }
                                break
                            }
                        }
                    }
                }
                $o.ClusterLogHits = $hits.ToArray()
                $o.ClusterLogCounts = $counts
            }
        }
    }
    [pscustomobject]@{ Computer = $env:COMPUTERNAME; Json = ($o | ConvertTo-Json -Depth 6 -Compress) }
}

$icmErr = $null
$nodeRaw = Invoke-Command -ComputerName $Computers -ScriptBlock $nodeCollector `
           -ArgumentList $StartTime, $EndTime, $clusterLogMinutes, ([bool]$SkipClusterLog) -ErrorAction SilentlyContinue -ErrorVariable icmErr
foreach ($e in @($icmErr)) {
    if ($e) {
        Add-Finding (Get-ShortName "$($e.TargetObject)") 'Collector' 'CRITICAL' 'Collection' 'remote OS/cluster collection failed' "$($e.Exception.Message)" '' `
            'This node could not be reached over WinRM: OS, storage and cluster evidence for it is missing from the verdict.' 'Enable-PSRemoting / firewall 5985; run from a cluster node; or run the workbook OS steps manually.' 'COLLECT_FAIL'
    }
}
$Nodes = @{}
foreach ($nr in @($nodeRaw)) { if ($nr) { $Nodes[(Get-ShortName $nr.Computer)] = $nr.Json | ConvertFrom-Json } }
$nodeRaw | Select-Object Computer, Json | Export-Csv (Join-Path $OutDir 'raw_node_collection.csv') -NoTypeInformation
#endregion

#region ---------------------------------------------------------------- 4. Receive SQL layer
$RoleOf = @{}
$sqlOk  = @{}
if ($sqlJobs) {
    Write-Host "  Waiting for SQL collectors ..."
    $null = Wait-Job -Job $sqlJobs -Timeout 1500
    foreach ($j in $sqlJobs) {
        $inst = $j.Name.Substring(4); $node = $InstToNode[$inst]
        $res = $null
        if ($j.State -eq 'Completed') { $res = Receive-Job $j -ErrorAction SilentlyContinue -ErrorVariable jerr }
        if (-not $res) {
            $why = if ($j.State -ne 'Completed') { "job state $($j.State)" } else { "$($jerr | Select-Object -First 1)" }
            if ($j.State -eq 'Failed') { $why = "$($j.ChildJobs[0].JobStateInfo.Reason.Message)" }
            Add-Finding $node 'SQL' 'CRITICAL' 'Collection' "SQL collector failed on $inst" $why '' `
                'No SQL-side evidence for this replica. If the instance is down or hung, that itself is a finding; Application-log SQL events are used as a fallback.' `
                'Check connectivity/permissions; SqlServer module installed; run AG_Diag_SQL.sql manually in SSMS.' 'COLLECT_FAIL'
            continue
        }
        $sqlOk[$node] = $true
        $res.Findings | Export-Csv (Join-Path $OutDir ("raw_sql_findings_{0}.csv" -f ($inst -replace '[\\:]', '_'))) -NoTypeInformation
        foreach ($f in $res.Findings) {
            $tag = "$($f.tag)"
            if ($tag -eq 'ROLE_PRIMARY')   { $RoleOf[$node] = 'PRIMARY' }
            if ($tag -eq 'ROLE_SECONDARY' -and -not $RoleOf.ContainsKey($node)) { $RoleOf[$node] = 'SECONDARY' }
            Add-Finding $node 'SQL' "$($f.severity)" "$($f.area)" ("{0} :: {1}" -f $f.object_name, $f.metric) "$($f.value)" "$($f.threshold)" "$($f.interpretation)" "$($f.next_step)" $tag
        }
        foreach ($t in $res.Timeline) {
            $tt = $null; try { $tt = [datetime]$t.event_time } catch { }
            if ($tt) { Add-Event $tt $node ("SQL " + $t.source) "$($t.event)" "$($t.severity)" "$($t.tag)" "$($t.detail)" }
        }
    }
    $sqlJobs | Remove-Job -Force
}
#endregion

#region ---------------------------------------------------------------- 5. Interpret node data
function Get-OsEventInfo([string]$prov, [int]$id, [int]$level) {
    $k = "$prov|$id"
    switch -Regex ($k) {
        '^(?i)disk\|153$'   { return @('WARNING', 'IO retried (disk 153)', 'OS_DISK_EVENT', 'The disk driver retried an IO that did not complete in time. Bursts of 153 = storage path latency (host-to-storage, SAN path, cloud storage). OS-side proof behind SQL 833.') }
        '\|129$'            { return @('CRITICAL', "Reset to device ($prov 129)", 'OS_DISK_EVENT', 'The storage port driver timed out an IO and reset the device: the LUN stopped responding. This is the classic host-storage communication failure that freezes SQL IO and can cascade into lease/heartbeat loss.') }
        '^(?i)disk\|51$'    { return @('CRITICAL', 'Paging IO error (disk 51)', 'OS_DISK_EVENT', 'An error was detected during a paging operation: storage path failure.') }
        '^(?i)disk\|157$'   { return @('CRITICAL', 'Disk surprise removed (157)', 'OS_DISK_EVENT', 'The disk disappeared from the OS. On Azure this can follow storage throttling or host events.') }
        '^(?i)disk\|(7|11|15)$' { return @('CRITICAL', "Disk error (disk $id)", 'OS_DISK_EVENT', 'Bad block / controller error / device not ready.') }
        '^(?i)(microsoft-windows-)?ntfs\|(50|57|137|140)$' { return @('CRITICAL', "NTFS write/flush failure ($id)", 'OS_DISK_EVENT', 'Windows could not flush data to the volume: storage failed mid-write; corruption risk.') }
        '^(?i)(microsoft-windows-)?ntfs\|' { return @('WARNING', "NTFS event ($id)", 'OS_DISK_EVENT', 'File system event on a volume; check which volume.') }
        '^(?i)(microsoft-windows-)?mpio\|' { return @('WARNING', "Multipath event ($id)", 'OS_DISK_EVENT', 'A storage path failed or failed over. Path failovers pause IO for seconds.') }
        '^(?i)(iscsiprt|msiscsi)\|' { return @('WARNING', "iSCSI event ($id)", 'OS_DISK_EVENT', 'iSCSI connection problem to the storage target.') }
        '^(?i)volsnap\|'    { return @('WARNING', "Volume snapshot event ($id)", 'IO_FROZEN', 'VSS snapshot problem or snapshot storage pressure (backup agent / VM snapshot).') }
        '^(?i)microsoft-windows-kernel-power\|41$' { return @('CRITICAL', 'Unexpected reboot (Kernel-Power 41)', 'OS_REBOOT', 'The node rebooted without a clean shutdown.') }
        '^(?i)eventlog\|6008$' { return @('CRITICAL', 'Unexpected shutdown (6008)', 'OS_REBOOT', 'The previous shutdown was unexpected.') }
        '^(?i)(tcpip|microsoft-windows-tcpip|ndis|netvsc|mlx\w*|e1\w*|vmxnet\w*)\|' { return @('WARNING', "Network stack event ($prov $id)", 'NET_EVENT', 'NIC reset, link change or TCP/IP error: AG traffic and cluster heartbeats are affected at the same moment.') }
        '^(?i)microsoft-windows-time-service\|' { return @('WARNING', "Time service event ($id)", 'TIME', 'Time sync problem: cross-node timelines and Kerberos can be off.') }
        default {
            if ($prov -match '(?i)stor|disk|vhdmp|lsi|nvme|volmgr') { return @('WARNING', "Storage stack event ($prov $id)", 'OS_DISK_EVENT', 'Storage driver warning/error; read the message.') }
            return @('INFO', "$prov $id", 'OS_EVENT', 'See message.')
        }
    }
}
$ClusterMap = @{
    1135 = @('CRITICAL', 'Node removed from membership (1135)', 'NODE_REMOVED', 'Other nodes stopped receiving this node''s heartbeats for SameSubnetThreshold x SameSubnetDelay. A node frozen by storage stalls, CPU starvation or dropped UDP 3343 looks exactly like this. It triggers AG failover when the node was primary.')
    1177 = @('CRITICAL', 'Quorum lost (1177)', 'QUORUM_LOST', 'Cluster lost quorum: all clustered roles, including the AG, go offline.')
    1069 = @('CRITICAL', 'Cluster resource failed (1069)', 'RESOURCE_FAILED', 'A clustered resource (AG, listener IP/name) failed; the cluster restarts it or fails the role over.')
    1146 = @('CRITICAL', 'RHS process terminated (1146)', 'RESOURCE_FAILED', 'Resource host crashed or was killed after a hung resource call (often IO-hang related).')
    1230 = @('CRITICAL', 'Resource call timed out (1230)', 'RESOURCE_FAILED', 'A resource did not respond to the cluster within its deadlock timeout.')
    1205 = @('CRITICAL', 'Role failed to come online (1205)', 'RESOURCE_FAILED', 'The clustered role could not be brought online on any node.')
    1254 = @('CRITICAL', 'Role exceeded failover threshold (1254)', 'FAILOVER_THRESHOLD', 'Too many failures in the failover period: the cluster stops trying and leaves the role failed.')
    1126 = @('WARNING', 'Cluster network interface unreachable (1126)', 'CLUSTER_NET', 'Heartbeat path to a node interface lost.')
    1127 = @('WARNING', 'Cluster network interface failed (1127)', 'CLUSTER_NET', 'A cluster network interface failed.')
    1129 = @('WARNING', 'Cluster network partitioned (1129)', 'CLUSTER_NET', 'Nodes can no longer see each other on a cluster network.')
    1130 = @('WARNING', 'Cluster network down (1130)', 'CLUSTER_NET', 'A cluster network went down.')
    1564 = @('WARNING', 'Witness access failed (1564)', 'QUORUM', 'File share witness unreachable: quorum is more fragile.')
    1641 = @('WARNING', 'Clustered role moved (1641)', 'ROLE_MOVED', 'The role (AG) moved between nodes: this is the failover.')
    1201 = @('INFO', 'Clustered role online (1201)', 'ROLE_ONLINE', 'Role brought online (end of failover).')
}
$SqlAppMap = @{
    833 = @('CRITICAL', 'IO > 15 s (833)', 'IO_STALL'); 1480 = @('CRITICAL', 'DB role change (1480)', 'ROLE_CHANGE'); 19406 = @('WARNING', 'Replica state change (19406)', 'STATE_CHANGE')
    19407 = @('CRITICAL', 'Lease expired (19407)', 'LEASE'); 19419 = @('CRITICAL', 'Lease renewal failed (19419)', 'LEASE'); 19421 = @('CRITICAL', 'Lease signal (19421)', 'LEASE')
    19422 = @('CRITICAL', 'Lease renewal (19422)', 'LEASE'); 35201 = @('WARNING', 'Connection timeout (35201)', 'CONN_TIMEOUT'); 35206 = @('WARNING', 'Connection timeout (35206)', 'CONN_TIMEOUT')
    35264 = @('CRITICAL', 'Data movement suspended (35264)', 'SUSPENDED'); 9002 = @('CRITICAL', 'Log full (9002)', 'LOG_FULL'); 1105 = @('CRITICAL', 'Filegroup full (1105)', 'DISK_FULL')
    823 = @('CRITICAL', 'IO error (823)', 'IO_ERROR'); 824 = @('CRITICAL', 'IO consistency error (824)', 'IO_ERROR')
}

$clusterDone = $false
$nodeUtc = @{}
foreach ($node in $Nodes.Keys) {
    $d = $Nodes[$node]
    $role = $RoleOf[$node]
    $nodeUtc[$node] = ConvertTo-LocalTime $d.NowUtc

    # uptime
    $boot = ConvertTo-LocalTime $d.LastBoot
    if ($boot -and $boot -ge $StartTime) {
        Add-Finding $node 'OS' 'CRITICAL' 'Uptime' 'last boot inside window' "$boot" '' 'The node rebooted inside the incident window. Any AG failover at that time is a consequence of the reboot; find why it rebooted.' 'System log 41/6008/1074, Azure Resource Health.' 'OS_REBOOT'
        Add-Event $boot $node 'OS' 'Node boot' 'CRITICAL' 'OS_REBOOT' 'Last boot time'
    }

    # volumes
    foreach ($v in @($d.Volumes)) {
        if (-not $v.CapacityGB) { continue }
        $pct = [math]::Round(100 * $v.FreeGB / $v.CapacityGB, 1)
        $sev = if ($pct -lt 5) { 'CRITICAL' } elseif ($pct -lt 15) { 'WARNING' } else { 'OK' }
        $interp = if ($sev -eq 'OK') { 'Enough free space.' }
                  elseif ($role -eq 'SECONDARY') { 'Secondary volume nearly full. When a log write or a replayed file growth cannot be satisfied here, the database stops synchronizing / suspends, the AG turns NOT_HEALTHY and the PRIMARY log cannot truncate until space is freed.' }
                  elseif ($role -eq 'PRIMARY') { 'Primary volume nearly full. With a lagging secondary the primary log keeps growing (AVAILABILITY_REPLICA); if this volume holds a log, the primary will stop.' }
                  else { 'Volume nearly full.' }
        Add-Finding $node 'OS' $sev 'Disk space' "$($v.Name) $($v.Label)" ("{0} % free ({1} of {2} GB)" -f $pct, $v.FreeGB, $v.CapacityGB) 'warn <15 %, crit <5 %' $interp `
            $(if ($sev -ne 'OK') { 'Free/extend now; keep volume sizes identical on all replicas; alert at 20 %.' }) $(if ($sev -eq 'CRITICAL') { 'DISK_FULL' } elseif ($sev -eq 'WARNING') { 'DISK_LOW' })
    }

    if ($d.TopProcesses) { Add-Finding $node 'OS' 'INFO' 'CPU' 'top processes now (% of machine)' ($d.TopProcesses -join ', ') '' 'A non-SQL process near the top (antivirus, backup, monitoring agent) steals CPU and IO from redo and lease renewal.' $null $null }

    # System events
    $grp = @{}
    foreach ($e in @($d.SystemEvents)) {
        if (-not $e) { continue }
        $info = Get-OsEventInfo $e.Provider ([int]$e.Id) ([int]$e.Level)
        $t = ConvertTo-LocalTime $e.Time
        if ($t) { Add-Event $t $node ("OS System: " + $e.Provider) $info[1] $info[0] $info[2] $e.Message }
        $key = $info[1]
        if (-not $grp.ContainsKey($key)) { $grp[$key] = [pscustomobject]@{ Info = $info; Count = 0; First = $t; Last = $t } }
        $g = $grp[$key]; $g.Count++
        if ($t -and (-not $g.First -or $t -lt $g.First)) { $g.First = $t }
        if ($t -and (-not $g.Last -or $t -gt $g.Last)) { $g.Last = $t }
    }
    foreach ($k in $grp.Keys) {
        $g = $grp[$k]; $sev = $g.Info[0]
        if ($g.Info[2] -eq 'OS_DISK_EVENT' -and $g.Count -ge 5 -and $sev -eq 'WARNING') { $sev = 'CRITICAL' }
        Add-Finding $node 'OS' $sev 'OS events' $k ("{0} events, first {1:yyyy-MM-dd HH:mm:ss}, last {2:yyyy-MM-dd HH:mm:ss}" -f $g.Count, $g.First, $g.Last) '0' $g.Info[3] 'Exact sequence in the Timeline; give storage/provider team these timestamps.' $g.Info[2]
    }

    # Cluster events
    $grp = @{}
    foreach ($e in @($d.ClusterEvents)) {
        if (-not $e) { continue }
        $id = [int]$e.Id
        $info = if ($ClusterMap.ContainsKey($id)) { $ClusterMap[$id] } elseif ([int]$e.Level -le 2) { @('WARNING', "Cluster error ($id)", 'CLUSTER_ERR', 'Failover cluster error; read the message.') } else { $null }
        if (-not $info) { continue }
        $t = ConvertTo-LocalTime $e.Time
        if ($t) { Add-Event $t $node 'Cluster event' $info[1] $info[0] $info[2] $e.Message }
        $key = $info[1]
        if (-not $grp.ContainsKey($key)) { $grp[$key] = [pscustomobject]@{ Info = $info; Count = 0; First = $t; Last = $t } }
        $g = $grp[$key]; $g.Count++
        if ($t -and (-not $g.First -or $t -lt $g.First)) { $g.First = $t }
        if ($t -and (-not $g.Last -or $t -gt $g.Last)) { $g.Last = $t }
    }
    foreach ($k in $grp.Keys) {
        $g = $grp[$k]
        Add-Finding $node 'Cluster' $g.Info[0] 'Cluster events' $k ("{0} events, first {1:yyyy-MM-dd HH:mm:ss}, last {2:yyyy-MM-dd HH:mm:ss}" -f $g.Count, $g.First, $g.Last) '0' $g.Info[3] 'See Timeline for what happened just before.' $g.Info[2]
    }

    # SQL Application-log events: only when the SQL layer could not run on this node
    if (-not $sqlOk[$node]) {
        foreach ($e in @($d.SqlAppEvents)) {
            if (-not $e) { continue }
            $m = $SqlAppMap[[int]$e.Id]; if (-not $m) { continue }
            $t = ConvertTo-LocalTime $e.Time
            if ($t) { Add-Event $t $node 'SQL (Application log)' $m[1] $m[0] $m[2] $e.Message }
        }
        $cnt = @($d.SqlAppEvents | Where-Object { $_ }).Count
        if ($cnt) { Add-Finding $node 'SQL' 'WARNING' 'Application log' 'SQL AG/IO events (fallback source)' "$cnt events" '' 'SQL layer did not run for this node; these Application-log entries stand in for the errorlog. See Timeline.' $null $null }
    }

    # NIC counters (cumulative)
    foreach ($ns in @($d.NetStats)) {
        if (-not $ns) { continue }
        $errs = [int64]$ns.ReceivedPacketErrors + [int64]$ns.OutboundPacketErrors
        $disc = [int64]$ns.ReceivedDiscardedPackets + [int64]$ns.OutboundDiscardedPackets
        if ($errs -gt 0 -or $disc -gt 1000) {
            Add-Finding $node 'Network' 'WARNING' 'NIC counters' $ns.Name ("errors {0}, discards {1} (since NIC reset)" -f $errs, $disc) 'errors 0' `
                'Packet errors/discards on the adapter. Discards often mean receive buffers overflow under load; errors point at driver, cable or virtual switch.' 'Compare over time; update NIC driver; check receive buffers/RSS.' 'NET_NIC_ERRORS'
        }
    }

    # Azure
    if ($d.Azure) {
        Add-Finding $node 'Azure' 'INFO' 'Azure VM' 'size / region / zone' ("{0} / {1} / {2}" -f $d.Azure.vmSize, $d.Azure.location, $d.Azure.zone) '' `
            'Running on Azure: VM-level and per-disk IOPS/throughput caps apply; when hit, latency and queue rise even though the disk is "fine". Platform host events can pause IO or the VM.' `
            'Azure portal for the window: VM > Metrics (VM Cached/Uncached Bandwidth & IOPS Consumed Percentage, Data Disk IOPS/Bandwidth Consumed Percentage), Activity Log, Resource Health (RCA kept ~72 h).' 'AZURE'
        foreach ($se in @($d.AzureScheduledEvents)) {
            if ($se) { Add-Finding $node 'Azure' 'WARNING' 'Azure scheduled events' "$($se.EventType) $($se.EventStatus)" "NotBefore $($se.NotBefore) $($se.Description)" '' 'Platform maintenance is scheduled or running for this VM (Freeze/Reboot/Redeploy). Freeze pauses the VM for seconds: enough for heartbeats/lease to be missed.' 'Coordinate: fail over manually beforehand, or rely on relaxed thresholds.' 'AZURE_EVENT' }
        }
    }

    # Cluster configuration (once)
    if ($d.Cluster -and -not $clusterDone) {
        $clusterDone = $true
        $cl = $d.Cluster
        $hbMs = [int]$cl.SameSubnetDelay * [int]$cl.SameSubnetThreshold
        $isAzure = [bool]$d.Azure
        $sev = if ($isAzure -and [int]$cl.SameSubnetThreshold -lt 40) { 'WARNING' } else { 'INFO' }
        Add-Finding 'CLUSTER' 'Cluster' $sev 'Cluster config' 'SameSubnet delay ms x threshold | CrossSubnet' `
            ("{0} x {1} = {2} ms | {3} x {4}" -f $cl.SameSubnetDelay, $cl.SameSubnetThreshold, $hbMs, $cl.CrossSubnetDelay, $cl.CrossSubnetThreshold) 'Azure recommended threshold 40' `
            ("A node is declared down after {0} s without heartbeats. {1}" -f ($hbMs / 1000), $(if ($sev -eq 'WARNING') { 'On Azure Microsoft recommends SameSubnetThreshold/CrossSubnetThreshold = 40 so short host or network hiccups do not remove nodes.' } else { '' })) `
            $(if ($sev -eq 'WARNING') { '(Get-Cluster).SameSubnetThreshold = 40; (Get-Cluster).CrossSubnetThreshold = 40  (change control; keep lease rule below).' }) 'CLUSTER_CONFIG'

        foreach ($n2 in @($d.ClusterNodes)) {
            if ($n2.State -ne 'Up') { Add-Finding 'CLUSTER' 'Cluster' 'CRITICAL' 'Cluster nodes' $n2.Name $n2.State 'Up' 'Node not Up: AG replicas on it cannot participate; automatic failover options shrink.' 'Get-ClusterNode; cluster log.' 'NODE_DOWN' }
        }
        foreach ($cn in @($d.ClusterNetworks)) {
            if ($cn.State -ne 'Up') { Add-Finding 'CLUSTER' 'Cluster' 'WARNING' 'Cluster networks' $cn.Name "$($cn.State) (role $($cn.Role))" 'Up' 'A cluster network is not Up: fewer heartbeat paths, higher risk of node removal.' $null 'CLUSTER_NET' }
        }
        if ($d.Quorum) { Add-Finding 'CLUSTER' 'Cluster' 'INFO' 'Quorum' 'type / witness' ("{0} / {1}" -f $d.Quorum.Type, $d.Quorum.Resource) '' 'Informational: with 2 nodes, the witness decides who survives a heartbeat loss.' $null $null }

        foreach ($ag in @($d.AgResources)) {
            $lease = [int]$ag.LeaseTimeout; $hct = [int]$ag.HealthCheckTimeout; $fcl = [int]$ag.FailureConditionLevel
            $leaseOk = ($lease / 2) -lt $hbMs
            $sev = if (-not $leaseOk) { 'WARNING' } elseif ($isAzure -and ($lease -lt 40000 -or $hct -lt 60000)) { 'WARNING' } else { 'INFO' }
            $interp = "Lease $lease ms: SQL/cluster must exchange a lease renewal at least every $($lease/2000) s. Health check $hct ms: no sp_server_diagnostics data for that long = failure. FCL $fcl."
            if (-not $leaseOk) { $interp += ' RULE BROKEN: half the lease timeout must be less than SameSubnetDelay x SameSubnetThreshold.' }
            if ($isAzure -and ($lease -lt 40000 -or $hct -lt 60000)) { $interp += ' On Azure, Microsoft''s relaxed settings are LeaseTimeout 40000, HealthCheckTimeout 60000, FCL 2, session timeout 20 s, max failures 6.' }
            Add-Finding 'CLUSTER' 'Cluster' $sev 'AG cluster resource' $ag.Name ("owner {0}, state {1}, lease {2}, health check {3}, FCL {4}, failover threshold {5} per {6} h" -f $ag.Owner, $ag.State, $lease, $hct, $fcl, $ag.FailoverThreshold, $ag.FailoverPeriod) `
                'default 20000 / 30000 / 3' $interp `
                $(if ($sev -eq 'WARNING') { 'Plan relaxed monitoring via change control: ALTER AVAILABILITY GROUP ... SET (HEALTH_CHECK_TIMEOUT = 60000, FAILURE_CONDITION_LEVEL = 2); LeaseTimeout in the AG resource properties (takes effect after offline/online).' }) 'AG_CONFIG'
        }
    }

    # Cluster log hits
    foreach ($h in @($d.ClusterLogHits)) {
        if (-not $h) { continue }
        $t = ConvertTo-LocalTime $h.Time
        $sev = switch ($h.Tag) { 'LEASE' { 'CRITICAL' } 'HEALTH_TIMEOUT' { 'CRITICAL' } 'NODE_REMOVED' { 'CRITICAL' } default { 'WARNING' } }
        if ($t) { Add-Event $t $node 'Cluster log' $h.Tag $sev $h.Tag $h.Line }
    }
    if ($d.ClusterLogCounts) {
        $cm = @{
            LEASE = 'Lease timeout detected by the AG resource DLL: SQL did not renew the lease in time (frozen/starved process, storage stall, paging).'
            HEALTH_TIMEOUT = 'AG health check failed / diagnostics heartbeat lost: sp_server_diagnostics results stopped arriving within HealthCheckTimeout. The resource DLL logs perf counters (CPU, memory, disk latency) right after this line: read them.'
            HADRAG_ERR = 'Errors from the AG resource DLL.'
            NODE_REMOVED = 'Node removed from membership / regroup.'
            NET_HEARTBEAT = 'Heartbeat or channel loss between nodes.'
            FAILOVER_ACTION = 'Resource control manager actions (failover, move, failure).' }
        foreach ($p in $d.ClusterLogCounts.PSObject.Properties) {
            $sev = if ($p.Name -in 'LEASE', 'HEALTH_TIMEOUT', 'NODE_REMOVED') { 'CRITICAL' } else { 'WARNING' }
            Add-Finding $node 'Cluster' $sev 'Cluster log' $p.Name "$($p.Value) lines in window" '0' $cm[$p.Name] "Open $($d.ClusterLogFile) on $node at the Timeline times." $p.Name
        }
    }
}

# time skew between nodes (approximate: includes WinRM latency)
$times = @($nodeUtc.GetEnumerator() | Where-Object { $_.Value })
if ($times.Count -ge 2) {
    $tk = $times | ForEach-Object { $_.Value.Ticks } | Measure-Object -Maximum -Minimum
    $skew = [math]::Round(($tk.Maximum - $tk.Minimum) / 1e7, 1)
    $sev = if ($skew -gt 5) { 'WARNING' } else { 'OK' }
    Add-Finding 'ALL' 'OS' $sev 'Time sync' 'approx. clock difference between nodes (s)' "$skew" '< 5 s (approximate)' `
        $(if ($sev -ne 'OK') { 'Clocks differ: cross-node timeline order may be misleading; Kerberos/cluster can misbehave.' } else { 'Clocks close enough for the timeline.' }) `
        $(if ($sev -ne 'OK') { 'w32tm /stripchart /computer:<othernode> /samples:5' }) $(if ($sev -ne 'OK') { 'TIME' })
}
#endregion

#region ---------------------------------------------------------------- 6. Cross-node verdict
$TagRows = @()
$TagRows += $Findings | Where-Object { $_.Tag -and $_.Severity -in 'CRITICAL', 'WARNING' } | ForEach-Object { [pscustomobject]@{ Node = $_.Node; Tag = $_.Tag; Time = $null } }
$TagRows += $Timeline | Where-Object { $_.Tag -and $_.Severity -in 'CRITICAL', 'WARNING' } | ForEach-Object { [pscustomobject]@{ Node = $_.Node; Tag = $_.Tag; Time = $_.Time } }
function Test-Tag([string[]]$Tags, [string]$Role) {
    $r = @($TagRows | Where-Object { $Tags -contains $_.Tag })
    if ($Role) { $r = @($r | Where-Object { $RoleOf[$_.Node] -eq $Role }) }
    return ($r.Count -gt 0)
}
function Get-Chain([string[]]$Tags) {
    $ev = $Timeline | Where-Object { $Tags -contains $_.Tag -and $_.Severity -in 'CRITICAL', 'WARNING' } | Sort-Object Time
    $firsts = $ev | Group-Object Node, Tag | ForEach-Object { $_.Group | Sort-Object Time | Select-Object -First 1 } | Sort-Object Time | Select-Object -First 12
    return (($firsts | ForEach-Object { '{0:HH:mm:ss} {1} {2}' -f $_.Time, $_.Node, $_.Event }) -join '  ->  ')
}

$storageTags = 'OS_DISK_EVENT', 'OS_DISK_LATENCY', 'IO_STALL', 'IO_ERROR', 'HEALTH_IO', 'LOG_WRITE_SLOW', 'IO_FROZEN'
$clusterTags = 'NODE_REMOVED', 'LEASE', 'HEALTH_TIMEOUT', 'ROLE_CHANGE', 'ROLE_MOVED', 'RESOURCE_FAILED', 'STATE_CHANGE', 'QUORUM_LOST', 'FAILOVER_THRESHOLD'
$verdicts = @()

if ((Test-Tag $storageTags) -and (Test-Tag $clusterTags)) {
    $s0 = $Timeline | Where-Object { $storageTags -contains $_.Tag -and $_.Severity -in 'CRITICAL', 'WARNING' } | Sort-Object Time | Select-Object -First 1
    $c0 = $Timeline | Where-Object { $clusterTags -contains $_.Tag -and $_.Severity -in 'CRITICAL', 'WARNING' } | Sort-Object Time | Select-Object -First 1
    $order = if ($s0 -and $c0 -and $s0.Time -le $c0.Time) { "First storage signal ({0:HH:mm:ss} on {1}: {2}) preceded the first cluster/AG failure signal ({3:HH:mm:ss} on {4}: {5}) by {6} s." -f $s0.Time, $s0.Node, $s0.Event, $c0.Time, $c0.Node, $c0.Event, [math]::Round(($c0.Time - $s0.Time).TotalSeconds) }
             elseif ($s0 -and $c0) { 'Cluster/AG failure signals appear BEFORE the first logged storage signal: storage may be a symptom, or it was not logged. Check network/heartbeat and CPU/memory rows too.' }
             else { 'Storage signals are live measurements (no timestamped storage events in the window).' }
    $verdicts += [pscustomobject]@{ Severity = 'CRITICAL'; Pattern = 'Storage latency -> lease / health-check / heartbeat loss -> automatic failover'
        Evidence = $order; Chain = (Get-Chain ($storageTags + $clusterTags))
        Meaning = 'Storage on a node stopped answering (retries/resets/833). SQL threads and the OS stall; lease renewal and sp_server_diagnostics miss their windows, heartbeats may be missed, the cluster declares the primary unhealthy and fails over to the synchronous secondary.'
        Action = 'Give the provider/storage team the exact storage timestamps (Timeline). On Azure: Resource Health, Activity Log, disk/VM consumed-percentage metrics. Consider relaxed cluster/AG thresholds. Keep secondary disk and VM size identical to primary.' }
}
if ((Test-Tag 'DISK_FULL', 'DISK_LOW', 'LOG_FULL', 'FILE_CANT_GROW' 'SECONDARY') -and (Test-Tag 'SUSPENDED', 'NOT_SYNC', 'NOT_HEALTHY', 'HARDEN_STALLED')) {
    $verdicts += [pscustomobject]@{ Severity = 'CRITICAL'; Pattern = 'Disk full on secondary -> synchronization stopped -> AG not healthy'
        Evidence = 'Low/no free space on a secondary node together with suspended / not-synchronizing databases.'; Chain = (Get-Chain 'DISK_FULL', 'LOG_FULL', 'SUSPENDED', 'STATE_CHANGE')
        Meaning = 'The secondary could not write log or grow a file, redo/harden failed and data movement suspended. The primary now keeps all log since then (AVAILABILITY_REPLICA).'
        Action = 'Free/extend space on the secondary, ALTER DATABASE ... SET HADR RESUME, watch primary log use until the queue drains; size replicas identically and alert on free space.' }
}
if ((Test-Tag 'LOG_GEN_HIGH' 'PRIMARY') -and ((Test-Tag 'LOG_WRITE_SLOW', 'DATA_READ_SLOW', 'OS_DISK_LATENCY', 'PAGEIOLATCH' 'SECONDARY') -or (Test-Tag 'FLOW_CONTROL', 'SYNC_COMMIT_SLOW'))) {
    $verdicts += [pscustomobject]@{ Severity = 'WARNING'; Pattern = 'Heavy log generation on primary + slow disk on secondary'
        Evidence = 'Primary log generation above threshold while the secondary shows slow log/data IO or flow control.'; Chain = ''
        Meaning = 'Neither half alone explains it: the workload burst produces log faster than the secondary storage can harden/redo it, so queues grow for the burst and drain slowly afterwards.'
        Action = 'Tame the burst (batching, resumable index ops, schedule) AND fix secondary IO (faster log volume, match primary disk tier/caps).' }
}
if (Test-Tag 'REDO_BLOCKED', 'REDO_STALLED') {
    $verdicts += [pscustomobject]@{ Severity = 'CRITICAL'; Pattern = 'Redo blocked on readable secondary'; Evidence = 'Redo thread blocked or redo rate zero with a queue.'; Chain = ''
        Meaning = 'A read query on the secondary holds a lock redo needs (DDL/index/stats work replayed from the primary).'; Action = 'Kill the blocker; move DDL/maintenance outside reporting hours; add report timeouts.' }
}
if ((Test-Tag 'NET_RETRANS', 'NET_RESENDS', 'CONN_TIMEOUT', 'CLUSTER_NET', 'NET_EVENT', 'NET_NIC_ERRORS', 'NET_HEARTBEAT') -and (Test-Tag 'SEND_Q', 'DISCONNECTED', 'NODE_REMOVED', 'FLOW_CONTROL')) {
    $verdicts += [pscustomobject]@{ Severity = 'WARNING'; Pattern = 'Network instability'; Evidence = 'Packet loss / NIC / cluster-network events together with send-queue growth, disconnects or node removal.'
        Chain = (Get-Chain 'NET_EVENT', 'CLUSTER_NET', 'NET_HEARTBEAT', 'CONN_TIMEOUT', 'NODE_REMOVED')
        Meaning = 'The path between replicas is dropping or delaying packets.'; Action = 'Network team: NIC/driver/firmware, virtual switch, firewall/IPS for 5022 and UDP 3343, MTU.' }
}
if ((Test-Tag 'OS_CPU', 'CPU_PRESSURE', 'THREADPOOL', 'OS_MEMORY_LOW', 'PAGING', 'MEMORY_LOW') -and (Test-Tag 'LEASE', 'HEALTH_TIMEOUT', 'REDO_Q', 'SEND_Q')) {
    $verdicts += [pscustomobject]@{ Severity = 'WARNING'; Pattern = 'CPU / memory starvation'; Evidence = 'CPU, worker or memory pressure alongside lease/health or queue findings.'; Chain = ''
        Meaning = 'The node is too busy (or paging) to renew the lease, answer health checks or keep up with redo.'; Action = 'Find the consumer (Top processes, SQL CPU); Lock Pages in Memory; right-size.' }
}
if (-not $verdicts) {
    $crit = @($Findings | Where-Object Severity -eq 'CRITICAL').Count; $warn = @($Findings | Where-Object Severity -eq 'WARNING').Count
    $verdicts += [pscustomobject]@{ Severity = $(if ($crit) { 'WARNING' } else { 'OK' }); Pattern = 'No composite pattern matched'
        Evidence = "$crit critical, $warn warning findings"; Chain = ''
        Meaning = 'No known multi-layer signature. If lag is transient, run again during the next occurrence (or with -StartTime/-EndTime around it).'
        Action = 'Read CRITICAL/WARNING findings; use the workbook step for the lagging hop.' }
}
#endregion

#region ---------------------------------------------------------------- 7. Output
$sevOrder = @{ CRITICAL = 0; WARNING = 1; INFO = 2; OK = 3 }
$FindingsSorted = $Findings | Sort-Object @{ e = { $sevOrder["$($_.Severity)"] } }, Layer, Node, Area
$TimelineSorted = $Timeline | Sort-Object Time

$FindingsSorted | Export-Csv (Join-Path $OutDir 'Findings.csv') -NoTypeInformation
$TimelineSorted | Export-Csv (Join-Path $OutDir 'Timeline.csv') -NoTypeInformation
$verdicts       | Export-Csv (Join-Path $OutDir 'Verdict.csv') -NoTypeInformation

$css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:20px;color:#222}
h1{font-size:20px} h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc}
table{border-collapse:collapse;width:100%;margin-top:6px} th{background:#f0f0f0;text-align:left}
td,th{border:1px solid #ddd;padding:4px 6px;vertical-align:top}
td.CRITICAL{background:#f8d7da;font-weight:600} td.WARNING{background:#fff3cd} td.OK{background:#d4edda} td.INFO{background:#e7f1ff}
</style>
'@
function Set-SevClass([string]$html) { return ($html -replace '<td>(CRITICAL|WARNING|INFO|OK)</td>', '<td class="$1">$1</td>') }
$roles = ($RoleOf.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
$head  = "<h1>AG holistic diagnostic</h1><p>Window: $StartTime to $EndTime &nbsp;|&nbsp; Nodes: $($Computers -join ', ') &nbsp;|&nbsp; Roles: $roles &nbsp;|&nbsp; Generated: $(Get-Date)</p>"
$h1 = Set-SevClass ($verdicts | ConvertTo-Html -Fragment -PreContent '<h2>1. Verdict</h2>' | Out-String)
$h2 = Set-SevClass ($FindingsSorted | Where-Object { $_.Severity -in 'CRITICAL', 'WARNING' } |
       Select-Object Severity, Layer, Node, Area, Check, Value, Interpretation, NextStep |
       ConvertTo-Html -Fragment -PreContent '<h2>2. Critical and warning findings (all layers)</h2>' | Out-String)
$h3 = Set-SevClass ($TimelineSorted | Where-Object { $_.Severity -in 'CRITICAL', 'WARNING' } |
       Select-Object @{ n = 'Time'; e = { $_.Time.ToString('yyyy-MM-dd HH:mm:ss.fff') } }, Node, Source, Event, Severity, Detail |
       ConvertTo-Html -Fragment -PreContent '<h2>3. Timeline (critical and warning, all nodes, local time)</h2><p>Read top-down: the first storage / network / CPU signal before the first lease, heartbeat or role-change line is the trigger candidate.</p>' | Out-String)
$h4 = Set-SevClass ($FindingsSorted | Select-Object Severity, Layer, Node, Area, Check, Value, Threshold, Interpretation |
       ConvertTo-Html -Fragment -PreContent '<h2>4. All findings</h2>' | Out-String)
$report = Join-Path $OutDir 'AGDiag_Report.html'
ConvertTo-Html -Head $css -Body ($head + $h1 + $h2 + $h3 + $h4) -Title 'AG diagnostic' | Out-File $report -Encoding utf8

Write-Host ''
Write-Host '=== VERDICT ===' -ForegroundColor Yellow
$verdicts | Format-List Severity, Pattern, Evidence, Chain, Meaning, Action
Write-Host '=== CRITICAL / WARNING ===' -ForegroundColor Yellow
$FindingsSorted | Where-Object { $_.Severity -in 'CRITICAL', 'WARNING' } | Format-Table Severity, Layer, Node, Area, Check, Value -AutoSize -Wrap
Write-Host "Report: $report" -ForegroundColor Green
Write-Host "CSVs:   $OutDir" -ForegroundColor Green
#endregion
