/*=====================================================================================
  AG_Diag_SQL.sql  -  Self-interpreting Availability Group health + lag diagnostic
  -------------------------------------------------------------------------------------
  Run on the PRIMARY and on EACH SECONDARY (SSMS, sqlcmd, or Invoke-AGDiag.ps1).
  Read-only. Creates #temp tables only. Runtime ~ @SampleSec + XE read time (30-90 s).

  Output (2 result sets):
    1. FINDINGS  - one row per check: severity, value, threshold, interpretation, next step
    2. TIMELINE  - errorlog / AlwaysOn_health / system_health events in the window,
                   local time, ready to merge with the other replica and the OS timeline

  Severity: 1 CRITICAL, 2 WARNING, 3 INFO, 4 OK   (OK rows hidden unless @ShowOK = 1)
  Tags (column 'tag') drive the correlation verdict at the end and in Invoke-AGDiag.ps1.
  Written for SQL Server 2016 SP2 and later. Validate in a lab before first production use.
=====================================================================================*/
SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

DECLARE @HoursBack        int   = 24;     -- look-back for errorlog / XE / job history
DECLARE @SampleSec        int   = 10;     -- delta sample length (waits, IO, counters)
DECLARE @ShowOK           bit   = 0;      -- 1 = also list passing checks
DECLARE @LogGenWarnKBps   bigint = 20480; -- 20 MB/s per DB = "heavy log generation" (tune per system)
DECLARE @ReadXE           bit   = 1;      -- 0 = skip AlwaysOn_health / system_health reads (faster)

DECLARE @Start   datetime = DATEADD(HOUR, -@HoursBack, GETDATE());
DECLARE @UtcOff  int      = DATEDIFF(MINUTE, SYSUTCDATETIME(), SYSDATETIME());   -- XE times are UTC
DECLARE @Delay   char(8)  = CONVERT(char(8), DATEADD(SECOND, @SampleSec, 0), 108);
DECLARE @Server  sysname  = @@SERVERNAME;
DECLARE @IsPrimaryAny bit = CASE WHEN EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states
                                              WHERE is_local = 1 AND role_desc = 'PRIMARY') THEN 1 ELSE 0 END;
DECLARE @IsSecondaryAny bit = CASE WHEN EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states
                                              WHERE is_local = 1 AND role_desc = 'SECONDARY') THEN 1 ELSE 0 END;

IF OBJECT_ID('tempdb..#f')  IS NOT NULL DROP TABLE #f;
IF OBJECT_ID('tempdb..#tl') IS NOT NULL DROP TABLE #tl;
CREATE TABLE #f (
    sev            tinyint        NOT NULL,
    area           varchar(40)    NOT NULL,
    object_name    nvarchar(400)  NULL,
    metric         nvarchar(200)  NULL,
    value          nvarchar(800)  NULL,
    threshold      nvarchar(200)  NULL,
    interpretation nvarchar(2000) NULL,
    next_step      nvarchar(1000) NULL,
    tag            varchar(40)    NULL);
CREATE TABLE #tl (
    event_time  datetime2(3)   NULL,
    source      varchar(40)    NOT NULL,
    event       nvarchar(200)  NULL,
    detail      nvarchar(2000) NULL,
    sev         tinyint        NOT NULL,
    tag         varchar(40)    NULL);

/*-------------------------------------------------------------------------------------
  0. Context
-------------------------------------------------------------------------------------*/
INSERT #f (sev, area, object_name, metric, value, interpretation, tag)
SELECT 3, 'Context', @Server, 'version / uptime',
       CONCAT(CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), ' ', CAST(SERVERPROPERTY('ProductUpdateLevel') AS nvarchar(128)),
              ' | up since ', CONVERT(varchar(19), si.sqlserver_start_time, 120),
              ' | cpus ', si.cpu_count, ' | mem MB ', si.physical_memory_kb / 1024),
       CONCAT('Local role(s): ', CASE WHEN @IsPrimaryAny = 1 THEN 'PRIMARY ' ELSE '' END,
              CASE WHEN @IsSecondaryAny = 1 THEN 'SECONDARY' ELSE '' END,
              '. A recent start time inside the incident window means the instance restarted (crash, patch or failover of an FCI).'),
       CASE WHEN @IsPrimaryAny = 1 THEN 'ROLE_PRIMARY' ELSE 'ROLE_SECONDARY' END
FROM sys.dm_os_sys_info si;

/*-------------------------------------------------------------------------------------
  1. AG configuration that decides failover sensitivity
-------------------------------------------------------------------------------------*/
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN ag.health_check_timeout < 30000 OR ag.failure_condition_level > 3 THEN 2 ELSE 3 END,
       'AG config', ag.name, 'failure_condition_level / health_check_timeout ms',
       CONCAT(ag.failure_condition_level, ' / ', ag.health_check_timeout),
       'default 3 / 30000; Azure relaxed 2 / 60000',
       CASE WHEN ag.health_check_timeout < 30000 THEN 'Health check timeout below default: brief stalls (storage, CPU, memory paging) can trigger automatic failover.'
            WHEN ag.failure_condition_level > 3 THEN 'FCL 4-5 fails over on resource / query-processing errors too; more sensitive than default.'
            ELSE 'Default or relaxed. With FCL 3, a system-component error or no sp_server_diagnostics data for health_check_timeout triggers failover.' END,
       'On Azure VMs Microsoft recommends HEALTH_CHECK_TIMEOUT = 60000 and FAILURE_CONDITION_LEVEL = 2; change gradually.',
       'AG_CONFIG'
FROM sys.availability_groups ag;

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN ar.session_timeout < 10 THEN 2 ELSE 3 END,
       'AG config', CONCAT(ag.name, ' / ', ar.replica_server_name),
       'mode / failover / session_timeout s / readable',
       CONCAT(ar.availability_mode_desc, ' / ', ar.failover_mode_desc, ' / ', ar.session_timeout, ' / ',
              ar.secondary_role_allow_connections_desc),
       'session_timeout default 10 (Azure relaxed 20)',
       CASE WHEN ar.session_timeout < 10 THEN 'Session timeout below default: short network or storage stalls disconnect the replica (35206).'
            WHEN ar.availability_mode_desc = 'SYNCHRONOUS_COMMIT' AND ar.failover_mode_desc = 'AUTOMATIC'
                 THEN 'Sync + automatic: this replica is an automatic failover target. Any health/lease failure on the primary can move the AG here.'
            ELSE 'Informational.' END,
       NULL, 'AG_CONFIG'
FROM sys.availability_replicas ar
JOIN sys.availability_groups ag ON ag.group_id = ar.group_id;

/*-------------------------------------------------------------------------------------
  2. Replica connection + health
-------------------------------------------------------------------------------------*/
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN ars.connected_state_desc = 'DISCONNECTED'           THEN 1
            WHEN ars.synchronization_health_desc = 'NOT_HEALTHY'      THEN 1
            WHEN ars.synchronization_health_desc = 'PARTIALLY_HEALTHY' THEN 2
            ELSE 4 END,
       'AG replica', CONCAT(ag.name, ' / ', ar.replica_server_name),
       'role / connected / sync health',
       CONCAT(ars.role_desc, ' / ', ars.connected_state_desc, ' / ', ars.synchronization_health_desc,
              CASE WHEN ars.last_connect_error_number IS NOT NULL
                   THEN CONCAT(' | last connect error ', ars.last_connect_error_number, ' at ',
                               CONVERT(varchar(19), ars.last_connect_error_timestamp, 120), ': ',
                               LEFT(ars.last_connect_error_description, 200)) ELSE '' END),
       'CONNECTED / HEALTHY',
       CASE WHEN ars.connected_state_desc = 'DISCONNECTED'
                 THEN 'Replica disconnected: log is not flowing. Send queue grows and the primary log cannot truncate (AVAILABILITY_REPLICA).'
            WHEN ars.synchronization_health_desc = 'NOT_HEALTHY'
                 THEN 'At least one database on this replica is not synchronizing or is suspended. Check the AG database rows below.'
            WHEN ars.synchronization_health_desc = 'PARTIALLY_HEALTHY'
                 THEN 'Some databases are not in the expected synchronization state.'
            ELSE 'Connected and healthy.' END,
       CASE WHEN ars.connected_state_desc = 'DISCONNECTED' OR ars.synchronization_health_desc <> 'HEALTHY'
            THEN 'Look at the TIMELINE for 35201/35206, lease and state-change events; run Invoke-AGDiag.ps1 for OS/cluster side.' END,
       CASE WHEN ars.connected_state_desc = 'DISCONNECTED' THEN 'DISCONNECTED'
            WHEN ars.synchronization_health_desc <> 'HEALTHY' THEN 'NOT_HEALTHY' END
FROM sys.dm_hadr_availability_replica_states ars
JOIN sys.availability_replicas ar ON ar.replica_id = ars.replica_id
JOIN sys.availability_groups ag   ON ag.group_id   = ars.group_id;

/*-------------------------------------------------------------------------------------
  3. Delta sample: waits, file IO, perf counters, pending IO  (one WAITFOR for all)
-------------------------------------------------------------------------------------*/
IF OBJECT_ID('tempdb..#w1')  IS NOT NULL DROP TABLE #w1;
IF OBJECT_ID('tempdb..#io1') IS NOT NULL DROP TABLE #io1;
IF OBJECT_ID('tempdb..#c1')  IS NOT NULL DROP TABLE #c1;
IF OBJECT_ID('tempdb..#pio') IS NOT NULL DROP TABLE #pio;

SELECT wait_type, waiting_tasks_count, wait_time_ms INTO #w1 FROM sys.dm_os_wait_stats;
SELECT database_id, file_id, num_of_reads, io_stall_read_ms, num_of_writes, io_stall_write_ms, num_of_bytes_written
INTO #io1 FROM sys.dm_io_virtual_file_stats(NULL, NULL);
SELECT object_name, counter_name, instance_name, cntr_value INTO #c1
FROM sys.dm_os_performance_counters
WHERE object_name LIKE '%Database Replica%' OR object_name LIKE '%Availability Replica%'
   OR (object_name LIKE '%:Databases%' AND counter_name IN ('Log Bytes Flushed/sec', 'Log Flush Wait Time', 'Log Flush Waits/sec'));

CREATE TABLE #pio (physical_name nvarchar(260), database_name sysname NULL, io_type nvarchar(60), io_pending_ms_ticks bigint);
INSERT #pio
SELECT mf.physical_name, DB_NAME(vfs.database_id), pio.io_type, pio.io_pending_ms_ticks
FROM sys.dm_io_pending_io_requests pio
JOIN sys.dm_io_virtual_file_stats(NULL, NULL) vfs ON vfs.file_handle = pio.io_handle
JOIN sys.master_files mf ON mf.database_id = vfs.database_id AND mf.file_id = vfs.file_id;

WAITFOR DELAY @Delay;

INSERT #pio
SELECT mf.physical_name, DB_NAME(vfs.database_id), pio.io_type, pio.io_pending_ms_ticks
FROM sys.dm_io_pending_io_requests pio
JOIN sys.dm_io_virtual_file_stats(NULL, NULL) vfs ON vfs.file_handle = pio.io_handle
JOIN sys.master_files mf ON mf.database_id = vfs.database_id AND mf.file_id = vfs.file_id;

/* 3a. Counter deltas -> per-second rates */
IF OBJECT_ID('tempdb..#c') IS NOT NULL DROP TABLE #c;
SELECT RTRIM(c2.object_name) AS object_name, RTRIM(c2.counter_name) AS counter_name,
       RTRIM(c2.instance_name) AS instance_name,
       (c2.cntr_value - c1.cntr_value) * 1.0 / @SampleSec AS per_sec,
       c2.cntr_value AS raw_now
INTO #c
FROM sys.dm_os_performance_counters c2
JOIN #c1 c1 ON c1.object_name = c2.object_name AND c1.counter_name = c2.counter_name
           AND c1.instance_name = c2.instance_name;

/* 3b. File IO deltas aggregated by volume + file type */
IF OBJECT_ID('tempdb..#io') IS NOT NULL DROP TABLE #io;
SELECT vs.volume_mount_point,
       CASE WHEN mf.type = 1 THEN 'LOG' ELSE 'DATA' END AS ftype,
       SUM(v.num_of_reads  - i.num_of_reads)       AS reads,
       SUM(v.io_stall_read_ms  - i.io_stall_read_ms)  AS read_stall_ms,
       SUM(v.num_of_writes - i.num_of_writes)      AS writes,
       SUM(v.io_stall_write_ms - i.io_stall_write_ms) AS write_stall_ms,
       SUM(v.num_of_bytes_written - i.num_of_bytes_written) AS bytes_written,
       SUM(v.num_of_reads)  AS reads_since_start,  SUM(v.io_stall_read_ms)  AS read_stall_since_start,
       SUM(v.num_of_writes) AS writes_since_start, SUM(v.io_stall_write_ms) AS write_stall_since_start
INTO #io
FROM sys.dm_io_virtual_file_stats(NULL, NULL) v
JOIN #io1 i ON i.database_id = v.database_id AND i.file_id = v.file_id
JOIN sys.master_files mf ON mf.database_id = v.database_id AND mf.file_id = v.file_id
CROSS APPLY sys.dm_os_volume_stats(v.database_id, v.file_id) vs
GROUP BY vs.volume_mount_point, CASE WHEN mf.type = 1 THEN 'LOG' ELSE 'DATA' END;

/*-------------------------------------------------------------------------------------
  4. AG database lag (rows describing secondaries: all of them on the primary,
     the local one on a secondary) + log generation vs throughput
-------------------------------------------------------------------------------------*/
;WITH d AS (
    SELECT ag.name AS ag_name, ar.replica_server_name AS rep, DB_NAME(drs.database_id) AS db,
           ar.availability_mode_desc AS mode, drs.synchronization_state_desc AS st,
           drs.is_suspended, drs.suspend_reason_desc,
           drs.log_send_queue_size AS sq, drs.log_send_rate AS sr,
           drs.redo_queue_size AS rq, drs.redo_rate AS rr,
           drs.last_hardened_time, drs.last_redone_time, drs.is_local,
           CAST(lg.per_sec / 1024.0 AS decimal(18,1)) AS log_gen_kbps     -- only meaningful on primary
    FROM sys.dm_hadr_database_replica_states drs
    JOIN sys.availability_replicas ar ON ar.replica_id = drs.replica_id
    JOIN sys.availability_groups ag   ON ag.group_id   = drs.group_id
    LEFT JOIN #c lg ON lg.object_name LIKE '%:Databases' AND lg.counter_name = 'Log Bytes Flushed/sec'
                   AND lg.instance_name = DB_NAME(drs.database_id)
    WHERE drs.is_primary_replica = 0)
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT v.sev, 'AG database', CONCAT(d.ag_name, ' / ', d.rep, ' / ', d.db), v.metric, v.value, v.threshold, v.interp, v.nxt, v.tag
FROM d
CROSS APPLY (VALUES
 -- suspended
 (CASE WHEN d.is_suspended = 1 THEN 1 ELSE 4 END,
  N'data movement suspended', CONCAT(d.is_suspended, N' ', d.suspend_reason_desc), N'0',
  CASE WHEN d.is_suspended = 1 THEN CONCAT(N'Suspended (', d.suspend_reason_desc, N'). Nothing is sent or redone; primary log is pinned. ',
       N'SUSPEND_FROM_REDO / SUSPEND_FROM_APPLY often means the secondary hit an error while redoing - classically a full data or log volume on the secondary (errors 1105/9002) or a failed file growth.')
       ELSE N'Not suspended.' END,
  CASE WHEN d.is_suspended = 1 THEN N'Check secondary volume free space and errorlog; fix the cause, then ALTER DATABASE [db] SET HADR RESUME;' END,
  CASE WHEN d.is_suspended = 1 THEN 'SUSPENDED' END),
 -- sync state
 (CASE WHEN d.st = 'NOT SYNCHRONIZING' THEN 1
       WHEN d.mode = 'SYNCHRONOUS_COMMIT' AND d.st <> 'SYNCHRONIZED' THEN 2 ELSE 4 END,
  N'synchronization state', d.st, CASE WHEN d.mode = 'SYNCHRONOUS_COMMIT' THEN N'SYNCHRONIZED' ELSE N'SYNCHRONIZING' END,
  CASE WHEN d.st = 'NOT SYNCHRONIZING' THEN N'Database not synchronizing: disconnected, suspended, or failed on the secondary.'
       WHEN d.mode = 'SYNCHRONOUS_COMMIT' AND d.st <> 'SYNCHRONIZED' THEN N'Sync replica is catching up: it is NOT a safe automatic failover target right now (possible data loss / failover blocked).'
       ELSE N'As expected for the commit mode.' END,
  NULL, CASE WHEN d.st = 'NOT SYNCHRONIZING' THEN 'NOT_SYNC' END),
 -- send queue
 (CASE WHEN d.sq > 1048576 THEN 1 WHEN d.sq > 102400 THEN 2 ELSE 4 END,
  N'log send queue KB (RPO exposure)', CONCAT(d.sq, N' KB, send rate ', d.sr, N' KB/s'), N'warn 100 MB, crit 1 GB',
  CASE WHEN d.sq > 102400 THEN CONCAT(N'Log not yet on the secondary = potential data loss on failover. ',
       CASE WHEN d.log_gen_kbps IS NOT NULL AND d.log_gen_kbps > d.sr THEN CONCAT(N'Primary is generating ', d.log_gen_kbps, N' KB/s, faster than it is sent (', d.sr, N' KB/s): send side (network or flow control from a slow secondary).')
            ELSE N'Check flow control, network and secondary harden latency.' END)
       ELSE N'Within normal range.' END,
  CASE WHEN d.sq > 102400 THEN N'Workbook Steps 4-5; in this report look at WAITS (flow control, HADR_SYNC_COMMIT) and the secondary LOG volume latency.' END,
  CASE WHEN d.sq > 102400 THEN 'SEND_Q' END),
 -- redo queue
 (CASE WHEN d.rq > 5242880 THEN 1 WHEN d.rq > 512000 THEN 2 ELSE 4 END,
  N'redo queue KB (RTO exposure)',
  CONCAT(d.rq, N' KB, redo rate ', d.rr, N' KB/s, est. catch-up ',
         CASE WHEN d.rr > 0 THEN CAST(CAST(d.rq * 1.0 / d.rr AS decimal(18,0)) AS varchar(20)) + ' s' ELSE 'n/a (rate 0)' END),
  N'warn 500 MB, crit 5 GB',
  CASE WHEN d.rq > 512000 AND ISNULL(d.rr, 0) = 0 THEN N'Redo queue with zero redo rate: redo is BLOCKED or stopped, not slow. Failover now would take long recovery.'
       WHEN d.rq > 512000 AND d.log_gen_kbps IS NOT NULL AND d.log_gen_kbps > d.rr THEN CONCAT(N'Primary generates ', d.log_gen_kbps, N' KB/s but secondary redoes ', d.rr, N' KB/s: redo capacity deficit, lag will keep growing while this workload runs.')
       WHEN d.rq > 512000 THEN N'Secondary receives log but replays it slowly: check redo threads, secondary data-volume reads, CPU.'
       ELSE N'Within normal range.' END,
  CASE WHEN d.rq > 512000 THEN N'Run this script on the secondary and read REDO + IO rows; workbook Step 6.' END,
  CASE WHEN d.rq > 512000 AND ISNULL(d.rr, 0) = 0 THEN 'REDO_STALLED' WHEN d.rq > 512000 THEN 'REDO_Q' END),
 -- log generation (primary only)
 (CASE WHEN d.log_gen_kbps >= @LogGenWarnKBps THEN 2 WHEN d.log_gen_kbps IS NULL THEN 4 ELSE 3 END,
  N'log generation KB/s (this sample)', CAST(d.log_gen_kbps AS nvarchar(30)), CONCAT(N'heavy >= ', @LogGenWarnKBps, N' KB/s'),
  CASE WHEN d.log_gen_kbps >= @LogGenWarnKBps THEN N'Heavy log generation on the primary (index maintenance, ETL, large DML). This alone creates transient lag; with a slow secondary disk it becomes sustained.'
       WHEN d.log_gen_kbps IS NOT NULL THEN N'Log generation for the sample window.' END,
  CASE WHEN d.log_gen_kbps >= @LogGenWarnKBps THEN N'Workbook Step 7a/7c/7d to name the session, job or query.' END,
  CASE WHEN d.log_gen_kbps >= @LogGenWarnKBps THEN 'LOG_GEN_HIGH' END),
 -- harden stall
 (CASE WHEN d.sq > 0 AND DATEDIFF(SECOND, d.last_hardened_time, SYSDATETIME()) > 60 THEN 1 ELSE 4 END,
  N'seconds since last harden', CAST(DATEDIFF(SECOND, d.last_hardened_time, SYSDATETIME()) AS nvarchar(20)), N'> 60 s with log pending',
  CASE WHEN d.sq > 0 AND DATEDIFF(SECOND, d.last_hardened_time, SYSDATETIME()) > 60 THEN N'Log is pending but nothing hardened for over a minute: disconnected, suspended, or secondary log volume stalled/full.' ELSE N'Hardening is progressing (or nothing to send).' END,
  NULL, CASE WHEN d.sq > 0 AND DATEDIFF(SECOND, d.last_hardened_time, SYSDATETIME()) > 60 THEN 'HARDEN_STALLED' END)
) v(sev, metric, value, threshold, interp, nxt, tag)
WHERE v.value IS NOT NULL;

/*-------------------------------------------------------------------------------------
  5. Disk space: every volume holding database files + files that cannot grow + log use
-------------------------------------------------------------------------------------*/
;WITH vol AS (
    SELECT vs.volume_mount_point,
           MAX(vs.total_bytes) AS total_bytes, MAX(vs.available_bytes) AS avail_bytes,
           MAX(CASE WHEN mf.type = 1 THEN 1 ELSE 0 END) AS has_log,
           MAX(CASE WHEN mf.type = 0 THEN 1 ELSE 0 END) AS has_data,
           MAX(CASE WHEN mf.database_id = 2 THEN 1 ELSE 0 END) AS has_tempdb
    FROM sys.master_files mf
    CROSS APPLY sys.dm_os_volume_stats(mf.database_id, mf.file_id) vs
    GROUP BY vs.volume_mount_point)
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN pct_free < 5 THEN 1 WHEN pct_free < 15 THEN 2 ELSE 4 END,
       'Disk space', volume_mount_point, 'free % / free GB / holds',
       CONCAT(pct_free, ' % / ', CAST(avail_bytes / 1073741824.0 AS decimal(18,1)), ' GB / ',
              CASE WHEN has_log = 1 THEN 'LOG ' ELSE '' END, CASE WHEN has_data = 1 THEN 'DATA ' ELSE '' END,
              CASE WHEN has_tempdb = 1 THEN 'TEMPDB' ELSE '' END),
       'warn < 15 %, crit < 5 %',
       CASE WHEN pct_free < 15 THEN
            CASE WHEN @IsSecondaryAny = 1 THEN
                 'Secondary volume nearly full. When a redo-replayed file growth or log write cannot be satisfied, the secondary database stops synchronizing / suspends (1105/9002), the AG turns NOT_HEALTHY, and the PRIMARY log can no longer truncate (log_reuse_wait = AVAILABILITY_REPLICA) until this is fixed.'
                 ELSE 'Primary volume nearly full. If a secondary is lagging, AVAILABILITY_REPLICA log reuse wait makes the log grow until this volume fills: that is a primary outage.' END
            ELSE 'Enough free space.' END,
       CASE WHEN pct_free < 15 THEN 'Free space or extend the volume now; keep primary and secondary volume sizes identical; alert at 20 %.' END,
       CASE WHEN pct_free < 5 THEN 'DISK_FULL' WHEN pct_free < 15 THEN 'DISK_LOW' END
FROM (SELECT *, CAST(100.0 * avail_bytes / NULLIF(total_bytes, 0) AS decimal(5,1)) AS pct_free FROM vol) x;

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT 2, 'Disk space', CONCAT(DB_NAME(mf.database_id), ' / ', mf.name),
       'file near max_size or autogrowth off',
       CONCAT('size MB ', mf.size / 128, ' | max MB ', CASE WHEN mf.max_size IN (-1, 268435456) THEN 'unlimited' ELSE CAST(mf.max_size / 128 AS varchar(20)) END,
              ' | growth ', mf.growth),
       'growth > 0 and size < 90 % of max',
       'This file cannot grow further. On a secondary, a growth replayed from the primary will fail and suspend the database.',
       'Raise max_size or pre-size the file on all replicas.', 'FILE_CANT_GROW'
FROM sys.master_files mf
WHERE mf.database_id > 4 AND mf.state = 0
  AND (mf.growth = 0 OR (mf.max_size NOT IN (-1, 268435456) AND mf.size >= 0.9 * mf.max_size));

IF OBJECT_ID('tempdb..#ls') IS NOT NULL DROP TABLE #ls;
CREATE TABLE #ls (dbname sysname, log_size_mb float, log_used_pct float, status int);
INSERT #ls EXEC ('DBCC SQLPERF(LOGSPACE) WITH NO_INFOMSGS');

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN ls.log_used_pct > 90 THEN 1 WHEN ls.log_used_pct > 75 THEN 2 ELSE 4 END,
       'Log space', ls.dbname, 'log used % / size MB / reuse wait',
       CONCAT(CAST(ls.log_used_pct AS decimal(5,1)), ' % / ', CAST(ls.log_size_mb AS decimal(18,0)), ' / ', d.log_reuse_wait_desc),
       'warn 75 %, crit 90 %',
       CASE WHEN ls.log_used_pct > 75 AND d.log_reuse_wait_desc = 'AVAILABILITY_REPLICA'
                 THEN 'Log filling because a secondary has not hardened/redone it. The AG lag is now a primary log-full risk.'
            WHEN ls.log_used_pct > 75 THEN CONCAT('Log filling; reuse wait = ', d.log_reuse_wait_desc, '.')
            ELSE 'OK.' END,
       CASE WHEN ls.log_used_pct > 75 THEN 'Fix the lag (or remove the dead replica from the AG as a last resort); make sure log backups run.' END,
       CASE WHEN ls.log_used_pct > 75 AND d.log_reuse_wait_desc = 'AVAILABILITY_REPLICA' THEN 'LOG_PINNED' END
FROM #ls ls
JOIN sys.databases d ON d.name = ls.dbname COLLATE DATABASE_DEFAULT
WHERE d.replica_id IS NOT NULL OR ls.log_used_pct > 75;

/*-------------------------------------------------------------------------------------
  6. IO latency by volume (sample window + since startup) and IO stuck right now
-------------------------------------------------------------------------------------*/
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT v.sev, 'IO latency', CONCAT(io.volume_mount_point, ' [', io.ftype, ']'), v.metric, v.value, v.threshold, v.interp, v.nxt, v.tag
FROM #io io
CROSS APPLY (SELECT CAST(io.write_stall_ms * 1.0 / NULLIF(io.writes, 0) AS decimal(10,1)) AS w_ms,
                    CAST(io.read_stall_ms  * 1.0 / NULLIF(io.reads, 0)  AS decimal(10,1)) AS r_ms,
                    CAST(io.write_stall_since_start * 1.0 / NULLIF(io.writes_since_start, 0) AS decimal(10,1)) AS w_ms_all,
                    CAST(io.read_stall_since_start  * 1.0 / NULLIF(io.reads_since_start, 0)  AS decimal(10,1)) AS r_ms_all) a
CROSS APPLY (VALUES
 -- log writes, sample window
 (CASE WHEN io.ftype = 'LOG' AND io.writes >= 10 AND a.w_ms > 20 THEN 1
       WHEN io.ftype = 'LOG' AND io.writes >= 10 AND a.w_ms > 5  THEN 2 ELSE 4 END,
  N'avg write ms (sample)', CONCAT(a.w_ms, N' ms over ', io.writes, N' writes, ', CAST(io.bytes_written / 1024.0 / @SampleSec AS decimal(18,0)), N' KB/s'),
  CASE WHEN io.ftype = 'LOG' THEN N'log: warn 5, crit 20 ms' ELSE N'data: info' END,
  CASE WHEN io.ftype = 'LOG' AND io.writes >= 10 AND a.w_ms > 5 THEN
       CASE WHEN @IsSecondaryAny = 1 THEN N'Slow log writes on the SECONDARY: every log block waits here before it is acknowledged -> HADR_SYNC_COMMIT on primary (sync) and flow control / send queue growth (both modes).'
            ELSE N'Slow log writes on the PRIMARY: WRITELOG waits for users, and log capture/send is delayed.' END
       WHEN io.ftype = 'LOG' THEN N'Log write latency OK.' ELSE N'Data file write latency (checkpoint / lazy writer / redo).' END,
  CASE WHEN io.ftype = 'LOG' AND io.writes >= 10 AND a.w_ms > 5 THEN N'Compare with OS LogicalDisk Avg. Disk sec/Write and queue for this volume (Invoke-AGDiag.ps1); check VM/disk IOPS and throughput caps.' END,
  CASE WHEN io.ftype = 'LOG' AND io.writes >= 10 AND a.w_ms > 5 THEN 'LOG_WRITE_SLOW' END),
 -- data reads, sample window
 (CASE WHEN io.ftype = 'DATA' AND io.reads >= 10 AND a.r_ms > 50 THEN 1
       WHEN io.ftype = 'DATA' AND io.reads >= 10 AND a.r_ms > 20 THEN 2 ELSE 4 END,
  N'avg read ms (sample)', CONCAT(a.r_ms, N' ms over ', io.reads, N' reads'),
  N'data: warn 20, crit 50 ms',
  CASE WHEN io.ftype = 'DATA' AND io.reads >= 10 AND a.r_ms > 20 THEN
       CASE WHEN @IsSecondaryAny = 1 THEN N'Slow data reads on the SECONDARY: redo must read pages before changing them, so redo rate drops and the redo queue grows. Reporting queries compete for the same IO.'
            ELSE N'Slow data reads on the primary (PAGEIOLATCH): user workload impact, not AG lag directly.' END
       ELSE N'Data read latency OK or too few reads to judge.' END,
  NULL, CASE WHEN io.ftype = 'DATA' AND io.reads >= 10 AND a.r_ms > 20 THEN 'DATA_READ_SLOW' END),
 -- since startup (history)
 (CASE WHEN (io.ftype = 'LOG' AND a.w_ms_all > 20) OR (io.ftype = 'DATA' AND a.r_ms_all > 50) THEN 2 ELSE 4 END,
  N'avg ms since startup (read / write)', CONCAT(a.r_ms_all, N' / ', a.w_ms_all),
  N'log write > 20 or data read > 50 = history of slowness',
  CASE WHEN (io.ftype = 'LOG' AND a.w_ms_all > 20) OR (io.ftype = 'DATA' AND a.r_ms_all > 50)
       THEN N'Cumulative average is high: past stalls (possibly the incident itself) are baked in even if the sample window looks clean.'
       ELSE N'Cumulative average normal.' END,
  NULL, NULL)
) v(sev, metric, value, threshold, interp, nxt, tag);

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN MAX(io_pending_ms_ticks) > 15000 THEN 1 WHEN MAX(io_pending_ms_ticks) > 1000 THEN 2 ELSE 3 END,
       'IO latency', physical_name, 'IO pending right now (max ms)',
       CONCAT(MAX(io_pending_ms_ticks), ' ms, ', COUNT(*), ' request(s)'),
       'warn 1 s, crit 15 s',
       'An IO has been outstanding this long at the OS/storage layer. > 15 s is the same condition as errorlog 833 and is enough to stall redo, lease renewal and health checks.',
       'Capture OS disk counters and System events (129/153) for this LUN now; engage storage / cloud provider.',
       CASE WHEN MAX(io_pending_ms_ticks) > 1000 THEN 'IO_STALL' END
FROM #pio
GROUP BY physical_name
HAVING MAX(io_pending_ms_ticks) > 200;

/*-------------------------------------------------------------------------------------
  7. Waits in the sample window, interpreted
-------------------------------------------------------------------------------------*/
IF OBJECT_ID('tempdb..#wmap') IS NOT NULL DROP TABLE #wmap;
CREATE TABLE #wmap (pat nvarchar(60), warn_avg float NULL, crit_avg float NULL, warn_ms_per_s float NULL, tag varchar(40) NULL,
                    interp nvarchar(600), nxt nvarchar(300));
INSERT #wmap VALUES
 (N'HADR_SYNC_COMMIT',           10,   50, NULL, 'SYNC_COMMIT_SLOW', N'Commits waiting for the sync secondary to harden and acknowledge. = network RTT + secondary log write + secondary CPU.', N'Check secondary LOG volume latency and network (workbook Steps 4-5, 9).'),
 (N'HADR_DATABASE_FLOW_CONTROL', NULL, NULL, 50,  'FLOW_CONTROL',     N'Database-level flow control: too many unacknowledged messages; the secondary is not keeping up.', N'Find the secondary bottleneck (harden or redo).'),
 (N'HADR_TRANSPORT_FLOW_CONTROL',NULL, NULL, 50,  'FLOW_CONTROL',     N'Transport-level flow control: the network/secondary cannot accept more log.', N'Network throughput and secondary harden latency.'),
 (N'WRITELOG',                   10,   20, NULL, 'WRITELOG_SLOW',    N'Local log flush latency on THIS node. On the primary = user commit latency; slow log volume.', N'OS disk latency for the log volume.'),
 (N'PAGEIOLATCH%',               20,   50, NULL, 'PAGEIOLATCH',      N'Waiting on data page reads from disk: slow data volume or not enough memory. On a secondary it slows redo.', N'Data volume latency, PLE, memory parity with primary.'),
 (N'PARALLEL_REDO_FLOW_CONTROL', NULL, NULL, 200, 'REDO_SATURATED',   N'Parallel redo workers saturated.', N'Secondary CPU/IO; break up huge transactions on primary.'),
 (N'PARALLEL_REDO_TRAN_TURN',    NULL, NULL, 200, 'REDO_SATURATED',   N'Redo serialized behind transaction ordering (often one very large transaction).', N'Batch large DML on the primary.'),
 (N'DIRTY_PAGE_TABLE_LOCK',      NULL, NULL, 50,  'REDO_READER_CONTENTION', N'Contention between parallel redo and read queries on the readable secondary.', N'Latest CU; reduce read workload.'),
 (N'LCK_M_SCH_M',                NULL, NULL, 10,  'REDO_BLOCKED',     N'Schema-modification lock waits. On a secondary this is typically redo waiting behind a reader (DDL/index op replayed).', N'See REDO rows; kill blocker.'),
 (N'THREADPOOL',                 NULL, NULL, 1,   'THREADPOOL',       N'Worker thread exhaustion: new tasks (including AG/HADR work) cannot get a thread.', N'Find the blocking chain / runaway parallelism.'),
 (N'SOS_SCHEDULER_YIELD',        NULL, NULL, 500, 'CPU_PRESSURE',     N'CPU pressure: tasks queueing for scheduler time.', N'CPU rows below; top CPU queries.'),
 (N'RESOURCE_SEMAPHORE',         NULL, NULL, 50,  'MEMORY_GRANTS',    N'Queries waiting for memory grants.', N'Large-grant queries; memory sizing.'),
 (N'LOG_RATE_GOVERNOR',          NULL, NULL, 10,  'LOG_GOVERNED',     N'Log generation throttled by a platform log-rate cap (Azure SQL MI / some VM SKUs).', N'Service tier / VM size.'),
 (N'IO_COMPLETION',              20,   50, NULL, 'IO_WAIT',          N'Non-page IO waits (sort spills, backup, log reads for capture). High avg = slow storage.', N'OS disk latency.'),
 (N'PREEMPTIVE_OS_WRITEFILEGATHER', NULL, NULL, 100, 'FILE_GROWTH', N'File growth zeroing (log growth / data without IFI). Stalls the whole file while it runs.', N'Pre-size files; enable IFI for data files.');

;WITH w AS (
    SELECT w2.wait_type,
           w2.waiting_tasks_count - w1.waiting_tasks_count AS waits,
           w2.wait_time_ms - w1.wait_time_ms AS wait_ms
    FROM sys.dm_os_wait_stats w2
    JOIN #w1 w1 ON w1.wait_type = w2.wait_type
    WHERE w2.wait_time_ms - w1.wait_time_ms > 0
      AND w2.wait_type NOT IN (N'HADR_WORK_QUEUE', N'HADR_LOGCAPTURE_WAIT', N'HADR_NOTIFICATION_DEQUEUE', N'HADR_TIMER_TASK',
            N'HADR_CLUSAPI_CALL', N'HADR_FILESTREAM_IOMGR_IOCOMPLETION', N'REDO_THREAD_PENDING_WORK', N'PARALLEL_REDO_WORKER_WAIT_WORK',
            N'LAZYWRITER_SLEEP', N'CHECKPOINT_QUEUE', N'REQUEST_FOR_DEADLOCK_SEARCH', N'LOGMGR_QUEUE', N'DIRTY_PAGE_POLL', N'WAITFOR',
            N'ONDEMAND_TASK_QUEUE', N'SP_SERVER_DIAGNOSTICS_SLEEP', N'CLR_AUTO_EVENT', N'CLR_MANUAL_EVENT', N'DISPATCHER_QUEUE_SEMAPHORE',
            N'FSAGENT', N'KSOURCE_WAKEUP', N'RESOURCE_QUEUE', N'SERVER_IDLE_CHECK', N'PREEMPTIVE_HADR_LEASE_MECHANISM', N'SOS_WORK_DISPATCHER',
            N'WAIT_XTP_OFFLINE_CKPT_NEW_LOG', N'PWAIT_ALL_COMPONENTS_INITIALIZED', N'XE_DISPATCHER_WAIT', N'XE_TIMER_EVENT', N'XE_LIVE_TARGET_TVF',
            N'WAIT_XTP_HOST_WAIT', N'WAIT_XTP_CKPT_CLOSE', N'CXCONSUMER', N'PVS_PREALLOCATE', N'MEMORY_ALLOCATION_EXT', N'PARALLEL_REDO_DRAIN_WORKER')
      AND w2.wait_type NOT LIKE N'SLEEP%' AND w2.wait_type NOT LIKE N'BROKER%' AND w2.wait_type NOT LIKE N'SQLTRACE%'
      AND w2.wait_type NOT LIKE N'QDS%'   AND w2.wait_type NOT LIKE N'FT_%'    AND w2.wait_type NOT LIKE N'PREEMPTIVE_XE%'),
ranked AS (
    SELECT w.*, CAST(w.wait_ms * 1.0 / NULLIF(w.waits, 0) AS decimal(12,1)) AS avg_ms,
           CAST(w.wait_ms * 1.0 / @SampleSec AS decimal(12,1)) AS ms_per_s,
           ROW_NUMBER() OVER (ORDER BY w.wait_ms DESC) AS rn
    FROM w)
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN m.crit_avg IS NOT NULL AND r.avg_ms >= m.crit_avg THEN 1
            WHEN m.warn_avg IS NOT NULL AND r.avg_ms >= m.warn_avg THEN 2
            WHEN m.warn_ms_per_s IS NOT NULL AND r.ms_per_s >= m.warn_ms_per_s THEN 2
            ELSE 3 END,
       'Waits (sample)', r.wait_type, 'waits / total ms / avg ms / ms per s',
       CONCAT(r.waits, ' / ', r.wait_ms, ' / ', r.avg_ms, ' / ', r.ms_per_s),
       CASE WHEN m.pat IS NULL THEN 'top-10 by time' ELSE CONCAT('avg warn ', m.warn_avg, ' crit ', m.crit_avg, ' | ms/s warn ', m.warn_ms_per_s) END,
       ISNULL(m.interp, 'Top wait in the window without a specific AG interpretation; look it up if it dominates.'),
       m.nxt,
       CASE WHEN (m.crit_avg IS NOT NULL AND r.avg_ms >= m.crit_avg) OR (m.warn_avg IS NOT NULL AND r.avg_ms >= m.warn_avg)
                 OR (m.warn_ms_per_s IS NOT NULL AND r.ms_per_s >= m.warn_ms_per_s) THEN m.tag END
FROM ranked r
OUTER APPLY (SELECT TOP (1) * FROM #wmap m WHERE r.wait_type COLLATE DATABASE_DEFAULT LIKE m.pat) m
WHERE r.rn <= 10 OR m.pat IS NOT NULL;

/*-------------------------------------------------------------------------------------
  8. AG counters in the sample window (flow control, resends, redo blocked)
-------------------------------------------------------------------------------------*/
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN c.counter_name = 'Redo blocked/sec' AND c.per_sec > 0 THEN 1
            WHEN c.counter_name = 'Flow Control Time (ms/sec)' AND c.per_sec > 100 THEN 1
            WHEN c.per_sec > 0 THEN 2 ELSE 4 END,
       'AG counters (sample)', CONCAT(c.counter_name, ' [', c.instance_name, ']'), 'per second',
       CAST(CAST(c.per_sec AS decimal(18,2)) AS nvarchar(40)), '> 0',
       CASE c.counter_name
            WHEN 'Redo blocked/sec'           THEN 'Redo thread was blocked by locks held by readers on this secondary during the sample.'
            WHEN 'Flow Control Time (ms/sec)' THEN 'Milliseconds per second log send was held back by flow control: the partner is not acknowledging fast enough.'
            WHEN 'Flow Control/sec'           THEN 'Flow control activations: the secondary is falling behind on harden or the network is saturated.'
            WHEN 'Resent Messages/sec'        THEN 'AG messages resent: packet loss / network instability between replicas.' END,
       CASE c.counter_name
            WHEN 'Redo blocked/sec'   THEN 'See REDO rows for the blocker; workbook Step 6b.'
            WHEN 'Resent Messages/sec' THEN 'Check TCP retransmits and NIC errors in the OS report.'
            ELSE 'Check secondary LOG volume latency and network.' END,
       CASE c.counter_name WHEN 'Redo blocked/sec' THEN 'REDO_BLOCKED' WHEN 'Resent Messages/sec' THEN 'NET_RESENDS' ELSE 'FLOW_CONTROL' END
FROM #c c
WHERE c.counter_name IN ('Redo blocked/sec', 'Flow Control Time (ms/sec)', 'Flow Control/sec', 'Resent Messages/sec')
  AND c.instance_name <> '_Total'
  AND c.per_sec > 0;

/*-------------------------------------------------------------------------------------
  9. Redo threads (secondary): blocked vs slow, parallel vs serial
-------------------------------------------------------------------------------------*/
IF @IsSecondaryAny = 1
BEGIN
    INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
    SELECT CASE WHEN r.blocking_session_id > 0 THEN 1 ELSE 3 END,
           'Redo', CONCAT(DB_NAME(r.database_id), ' spid ', r.session_id, ' (', r.command, ')'),
           'wait / blocker',
           CONCAT(ISNULL(r.wait_type, 'running'), ' ', r.wait_time, ' ms',
                  CASE WHEN r.blocking_session_id > 0
                       THEN CONCAT(' | blocked by spid ', r.blocking_session_id, ' ', s.login_name, ' / ', s.program_name, ' / ', s.host_name) ELSE '' END),
           'no blocker',
           CASE WHEN r.blocking_session_id > 0
                THEN 'Redo is BLOCKED by a session on this secondary (usually a report holding Sch-S while the primary ran DDL/index/stats work). Redo queue grows at the full log generation rate until the blocker ends.'
                WHEN r.wait_type LIKE 'PAGEIOLATCH%' THEN 'Redo waiting on data page reads: IO-bound redo.'
                ELSE 'Redo thread state for reference.' END,
           CASE WHEN r.blocking_session_id > 0 THEN 'Confirm with owner, KILL the blocker; move DDL/maintenance away from reporting hours.' END,
           CASE WHEN r.blocking_session_id > 0 THEN 'REDO_BLOCKED' WHEN r.wait_type LIKE 'PAGEIOLATCH%' THEN 'PAGEIOLATCH' END
    FROM sys.dm_exec_requests r
    LEFT JOIN sys.dm_exec_sessions s ON s.session_id = r.blocking_session_id
    WHERE (r.command = 'DB STARTUP' OR r.command LIKE '%REDO%')
      AND (r.blocking_session_id > 0 OR r.command = 'DB STARTUP');

    INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
    SELECT CASE WHEN SUM(CASE WHEN r.command LIKE 'PARALLEL REDO%' THEN 1 ELSE 0 END) = 0 THEN 2 ELSE 4 END,
           'Redo', DB_NAME(r.database_id), 'parallel redo workers',
           CAST(SUM(CASE WHEN r.command LIKE 'PARALLEL REDO%' THEN 1 ELSE 0 END) AS nvarchar(10)), '> 0',
           CASE WHEN SUM(CASE WHEN r.command LIKE 'PARALLEL REDO%' THEN 1 ELSE 0 END) = 0
                THEN 'Serial redo for this database (TF 3459, or the instance redo worker pool is used up by many AG databases). Serial redo is a common cause of sustained redo lag.'
                ELSE 'Parallel redo active.' END,
           NULL,
           CASE WHEN SUM(CASE WHEN r.command LIKE 'PARALLEL REDO%' THEN 1 ELSE 0 END) = 0 THEN 'SERIAL_REDO' END
    FROM sys.dm_exec_requests r
    WHERE r.command = 'DB STARTUP' OR r.command LIKE '%REDO%'
    GROUP BY r.database_id;
END;

/*-------------------------------------------------------------------------------------
  10. CPU, workers, memory
-------------------------------------------------------------------------------------*/
;WITH rb AS (
    SELECT TOP (10)
           x.rec.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS sql_cpu,
           100 - x.rec.value('(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]', 'int')
               - x.rec.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS other_cpu
    FROM (SELECT [timestamp], CONVERT(xml, record) AS rec
          FROM sys.dm_os_ring_buffers
          WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR' AND record LIKE N'%<SystemHealth>%') x
    ORDER BY x.[timestamp] DESC)
INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN MAX(sql_cpu + other_cpu) >= 95 THEN 1 WHEN AVG(sql_cpu + other_cpu) >= 80 OR AVG(other_cpu) >= 20 THEN 2 ELSE 4 END,
       'CPU', @Server, 'last 10 min: avg/max SQL %, avg/max other %',
       CONCAT(AVG(sql_cpu), ' / ', MAX(sql_cpu), ' | ', AVG(other_cpu), ' / ', MAX(other_cpu)),
       'total avg < 80, other < 20',
       CASE WHEN MAX(sql_cpu + other_cpu) >= 95 THEN 'CPU pegged: redo, log harden, lease renewal and sp_server_diagnostics all compete; pegged CPU is a documented lease-timeout cause.'
            WHEN AVG(other_cpu) >= 20 THEN 'A non-SQL process is using significant CPU (antivirus, backup agent, monitoring).'
            WHEN AVG(sql_cpu + other_cpu) >= 80 THEN 'Sustained high CPU.'
            ELSE 'CPU OK.' END,
       CASE WHEN MAX(sql_cpu + other_cpu) >= 80 OR AVG(other_cpu) >= 20 THEN 'OS report top processes; top CPU queries on this node.' END,
       CASE WHEN MAX(sql_cpu + other_cpu) >= 95 OR AVG(sql_cpu + other_cpu) >= 80 THEN 'CPU_PRESSURE' END
FROM rb;

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN SUM(work_queue_count) > 0 THEN 1 WHEN SUM(runnable_tasks_count) > 2 * COUNT(*) THEN 2 ELSE 4 END,
       'CPU', @Server, 'runnable tasks / tasks waiting for a worker / workers used / max',
       CONCAT(SUM(runnable_tasks_count), ' / ', SUM(work_queue_count), ' / ', SUM(current_workers_count), ' / ',
              (SELECT max_workers_count FROM sys.dm_os_sys_info)),
       'waiting for worker = 0; runnable < 2 per scheduler',
       CASE WHEN SUM(work_queue_count) > 0 THEN 'Worker thread exhaustion now: HADR and redo tasks can be starved.'
            WHEN SUM(runnable_tasks_count) > 2 * COUNT(*) THEN 'Runnable queue is long: CPU pressure.'
            ELSE 'OK.' END,
       NULL, CASE WHEN SUM(work_queue_count) > 0 THEN 'THREADPOOL' END
FROM sys.dm_os_schedulers
WHERE status = 'VISIBLE ONLINE';

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT CASE WHEN ple.cntr_value < 300 THEN 2 ELSE 3 END,
       'Memory', @Server, 'page life expectancy s / memory grants pending',
       CONCAT(ple.cntr_value, ' / ', ISNULL(mgp.cntr_value, 0)),
       'PLE trend matters more than a number',
       CASE WHEN ple.cntr_value < 300 THEN 'Pages leave the buffer pool quickly: redo on a secondary has to read more from disk. Common when the secondary has less memory than the primary.'
            ELSE 'Informational.' END,
       NULL, CASE WHEN ple.cntr_value < 300 THEN 'MEMORY_LOW' END
FROM sys.dm_os_performance_counters ple
LEFT JOIN sys.dm_os_performance_counters mgp
       ON mgp.object_name LIKE '%Memory Manager%' AND mgp.counter_name = 'Memory Grants Pending'
WHERE ple.object_name LIKE '%Buffer Manager%' AND ple.counter_name = 'Page life expectancy';

/*-------------------------------------------------------------------------------------
  11. Trace flags that change AG behaviour
-------------------------------------------------------------------------------------*/
IF OBJECT_ID('tempdb..#tf') IS NOT NULL DROP TABLE #tf;
CREATE TABLE #tf (TraceFlag int, Status int, Global int, Session int);
INSERT #tf EXEC ('DBCC TRACESTATUS(-1) WITH NO_INFOMSGS');
INSERT #f (sev, area, object_name, metric, value, interpretation, tag)
SELECT 2, 'Config', @Server, 'trace flag', CAST(TraceFlag AS nvarchar(10)),
       CASE TraceFlag WHEN 3459 THEN 'Parallel redo disabled: single-threaded redo per database.'
                      WHEN 1462 THEN 'Log stream compression disabled for async replicas: more bytes on the wire.'
                      WHEN 9592 THEN 'Log stream compression enabled for sync replicas: less bandwidth, more CPU and latency.'
                      WHEN 9567 THEN 'Compression for automatic seeding enabled.' END,
       'TRACE_FLAG'
FROM #tf WHERE TraceFlag IN (3459, 1462, 9592, 9567) AND Global = 1;

/*-------------------------------------------------------------------------------------
  12. Errorlog: signatures in the window -> TIMELINE + counts in FINDINGS
-------------------------------------------------------------------------------------*/
IF OBJECT_ID('tempdb..#el')  IS NOT NULL DROP TABLE #el;
IF OBJECT_ID('tempdb..#pat') IS NOT NULL DROP TABLE #pat;
CREATE TABLE #el (LogDate datetime, ProcessInfo nvarchar(100), LogText nvarchar(max));
BEGIN TRY INSERT #el EXEC sys.xp_readerrorlog 0, 1, NULL, NULL, @Start, NULL; END TRY BEGIN CATCH END CATCH;
BEGIN TRY INSERT #el EXEC sys.xp_readerrorlog 1, 1, NULL, NULL, @Start, NULL; END TRY BEGIN CATCH END CATCH;
BEGIN TRY INSERT #el EXEC sys.xp_readerrorlog 2, 1, NULL, NULL, @Start, NULL; END TRY BEGIN CATCH END CATCH;

CREATE TABLE #pat (pat nvarchar(200), label nvarchar(100), sev tinyint, tag varchar(40), interp nvarchar(600));
INSERT #pat VALUES
 (N'%I/O requests taking longer than 15 seconds%', N'IO > 15 s (833)', 1, 'IO_STALL',
  N'Storage did not complete IO for 15+ s. On an AG node this precedes lease/health-check timeouts, replica disconnects and automatic failover.'),
 (N'%I/O is frozen on database%', N'IO frozen (VSS)', 2, 'IO_FROZEN',
  N'A VSS snapshot (backup agent, VM snapshot) froze IO. Long freezes stall log hardening and redo.'),
 (N'%lease between availability group%expired%', N'Lease expired (19407)', 1, 'LEASE',
  N'SQL Server and the cluster did not exchange lease renewals within LeaseTimeout. Causes: OS unresponsive, pegged CPU, paging, storage stall, cluster/quorum loss. The AG goes RESOLVING and may fail over.'),
 (N'%renewal of the lease between availability group%', N'Lease renewal failed (19419)', 1, 'LEASE',
  N'Lease could not be renewed because it was no longer valid: the node was already late (see 19407).'),
 (N'%Error: 19421%', N'Lease signal not received (19421)', 1, 'LEASE', N'SQL did not receive the cluster process event signal within the lease period.'),
 (N'%Error: 19422%', N'Lease renewal error (19422)', 1, 'LEASE', N'Lease renewal failed.'),
 (N'%Error: 35201%', N'Connection timeout (35201)', 2, 'CONN_TIMEOUT', N'Could not establish the HADR connection to a replica within session_timeout.'),
 (N'%Error: 35206%', N'Connection timeout (35206)', 2, 'CONN_TIMEOUT', N'An established HADR connection timed out: network or the partner stalled (storage/CPU).'),
 (N'%Error: 35264%', N'Data movement suspended (35264)', 1, 'SUSPENDED', N'Data movement for a database was suspended (manual or error).'),
 (N'%Error: 35265%', N'Data movement resumed (35265)', 3, 'RESUMED', N'Data movement resumed.'),
 (N'%changing roles from%', N'Database role change (1480)', 1, 'ROLE_CHANGE', N'A database changed role: this is the failover itself (or a manual one). Everything just before it is your root-cause window.'),
 (N'%The state of the local availability replica%', N'Replica state change (19406)', 2, 'STATE_CHANGE', N'Local replica changed state (e.g. PRIMARY_NORMAL -> RESOLVING_NORMAL).'),
 (N'%Error: 9002%', N'Log full (9002)', 1, 'LOG_FULL', N'Transaction log full. On the secondary this suspends synchronization; on the primary writes stop.'),
 (N'%Error: 1105%', N'Filegroup full (1105)', 1, 'DISK_FULL', N'Could not allocate space: volume or file max size reached. On a secondary, redo fails and the database suspends.'),
 (N'%Error: 5149%', N'File growth failed (5149)', 1, 'DISK_FULL', N'OS reported an error while growing a file (typically disk full).'),
 (N'%Error: 823%', N'IO error (823)', 1, 'IO_ERROR', N'Hard IO error from the OS: storage path or device failure.'),
 (N'%Error: 824%', N'IO consistency error (824)', 1, 'IO_ERROR', N'Logical consistency IO error: possible corruption; run CHECKDB, check storage.'),
 (N'%non-yielding%', N'Non-yielding scheduler', 1, 'NONYIELD', N'A scheduler stopped yielding (often stuck IO, driver or CPU starvation). Can delay lease/health checks.'),
 (N'%process memory has been paged out%', N'Working set paged out', 1, 'PAGING', N'SQL memory was paged to disk: documented lease-timeout cause. Enable Lock Pages in Memory, check OS memory.'),
 (N'%Always On Availability Groups connection with%', N'AG connection event', 3, 'CONN_EVENT', N'HADR connection established or lost with a partner replica.');

INSERT #tl (event_time, source, event, detail, sev, tag)
SELECT TOP (400) e.LogDate, 'SQL errorlog', p.label, LEFT(e.LogText, 1000), p.sev, p.tag
FROM #el e
JOIN #pat p ON e.LogText LIKE p.pat
WHERE e.LogDate >= @Start
ORDER BY e.LogDate DESC;

INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
SELECT p.sev, 'Errorlog', p.label, CONCAT('count in last ', @HoursBack, ' h'),
       CONCAT(COUNT(*), ' | first ', CONVERT(varchar(19), MIN(e.LogDate), 120), ' | last ', CONVERT(varchar(19), MAX(e.LogDate), 120)),
       '0', p.interp, 'See TIMELINE for exact sequence across nodes.', p.tag
FROM #el e
JOIN #pat p ON e.LogText LIKE p.pat
WHERE e.LogDate >= @Start
GROUP BY p.sev, p.label, p.interp, p.tag;

/*-------------------------------------------------------------------------------------
  13. AlwaysOn_health + system_health (sp_server_diagnostics) -> TIMELINE
-------------------------------------------------------------------------------------*/
IF @ReadXE = 1
BEGIN
    BEGIN TRY
        ;WITH x AS (
            SELECT object_name, CAST(event_data AS xml) AS ed
            FROM sys.fn_xe_file_target_read_file('AlwaysOn_health*.xel', NULL, NULL, NULL)
            WHERE object_name IN ('availability_replica_state_change', 'availability_group_lease_expired',
                                  'error_reported', 'lock_redo_blocked', 'alwayson_ddl_executed',
                                  'hadr_db_partner_set_sync_state'))
        INSERT #tl (event_time, source, event, detail, sev, tag)
        SELECT DATEADD(MINUTE, @UtcOff, ed.value('(event/@timestamp)[1]', 'datetime2')),
               'AlwaysOn_health', object_name,
               LEFT(CONCAT(
                   ed.value('(event/data[@name="availability_group_name"]/value)[1]', 'nvarchar(128)'), ' ',
                   ed.value('(event/data[@name="previous_state"]/text)[1]', 'nvarchar(60)'), ' -> ',
                   ed.value('(event/data[@name="current_state"]/text)[1]', 'nvarchar(60)'), ' ',
                   ed.value('(event/data[@name="error_number"]/value)[1]', 'int'), ' ',
                   ed.value('(event/data[@name="message"]/value)[1]', 'nvarchar(1000)'), ' ',
                   ed.value('(event/data[@name="statement"]/value)[1]', 'nvarchar(500)')), 1000),
               CASE object_name WHEN 'availability_group_lease_expired' THEN 1
                                WHEN 'lock_redo_blocked' THEN 1
                                WHEN 'availability_replica_state_change' THEN 2 ELSE 3 END,
               CASE object_name WHEN 'availability_group_lease_expired' THEN 'LEASE'
                                WHEN 'lock_redo_blocked' THEN 'REDO_BLOCKED'
                                WHEN 'availability_replica_state_change' THEN 'STATE_CHANGE'
                                WHEN 'alwayson_ddl_executed' THEN 'AG_DDL' ELSE 'XE_ERROR' END
        FROM x
        WHERE DATEADD(MINUTE, @UtcOff, ed.value('(event/@timestamp)[1]', 'datetime2')) >= @Start;
    END TRY BEGIN CATCH
        INSERT #f (sev, area, metric, value) VALUES (3, 'Errorlog', 'AlwaysOn_health read failed', ERROR_MESSAGE());
    END CATCH;

    BEGIN TRY
        ;WITH x AS (
            SELECT CAST(event_data AS xml) AS ed
            FROM sys.fn_xe_file_target_read_file('system_health*.xel', NULL, NULL, NULL)
            WHERE object_name = 'sp_server_diagnostics_component_result')
        INSERT #tl (event_time, source, event, detail, sev, tag)
        SELECT t, 'system_health', CONCAT('sp_server_diagnostics ', comp, ' = ', st),
               'Health-check component not clean. With FCL 3 a SYSTEM error, and with any FCL no health data for health_check_timeout, triggers AG failover.',
               CASE WHEN st = 'ERROR' THEN 1 ELSE 2 END,
               CASE WHEN comp LIKE '%IO%' THEN 'HEALTH_IO' ELSE 'HEALTH_COMPONENT' END
        FROM (SELECT DATEADD(MINUTE, @UtcOff, ed.value('(event/@timestamp)[1]', 'datetime2')) AS t,
                     UPPER(ed.value('(event/data[@name="component"]/text)[1]', 'nvarchar(60)')) AS comp,
                     UPPER(ed.value('(event/data[@name="state"]/text)[1]', 'nvarchar(60)'))     AS st
              FROM x) s
        WHERE s.t >= @Start AND s.st IN ('WARNING', 'ERROR');
    END TRY BEGIN CATCH
        INSERT #f (sev, area, metric, value) VALUES (3, 'Errorlog', 'system_health read failed', ERROR_MESSAGE());
    END CATCH;

    INSERT #f (sev, area, object_name, metric, value, threshold, interpretation, next_step, tag)
    SELECT MIN(sev), 'XE history', CONCAT(source, ': ', event), CONCAT('count in last ', @HoursBack, ' h'),
           CONCAT(COUNT(*), ' | first ', CONVERT(varchar(19), MIN(event_time), 120), ' | last ', CONVERT(varchar(19), MAX(event_time), 120)),
           '0',
           CASE WHEN MAX(tag) = 'REDO_BLOCKED' THEN 'Historical proof that redo was blocked by readers on this secondary.'
                WHEN MAX(tag) = 'LEASE' THEN 'Lease expired: AG went to RESOLVING; see the OS/cluster timeline right before it.'
                WHEN MAX(tag) = 'STATE_CHANGE' THEN 'Replica role/state changed (failover or reconnect).'
                WHEN MAX(tag) LIKE 'HEALTH%' THEN MAX(detail)
                ELSE 'See TIMELINE.' END,
           NULL, MAX(tag)
    FROM #tl
    WHERE source IN ('AlwaysOn_health', 'system_health') AND sev <= 2
    GROUP BY source, event;
END;

/*-------------------------------------------------------------------------------------
  14. Correlation verdict (this node only; Invoke-AGDiag.ps1 correlates across nodes)
-------------------------------------------------------------------------------------*/
DECLARE @tags TABLE (tag varchar(40) PRIMARY KEY);
INSERT @tags SELECT DISTINCT tag FROM #f  WHERE tag IS NOT NULL AND sev <= 2
       UNION SELECT DISTINCT tag FROM #tl WHERE tag IS NOT NULL AND sev <= 2;

DECLARE @hStorage bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag IN ('IO_STALL', 'IO_ERROR', 'LOG_WRITE_SLOW', 'HEALTH_IO', 'NONYIELD'))
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('LEASE', 'ROLE_CHANGE', 'STATE_CHANGE')) THEN 1 ELSE 0 END;
DECLARE @hDiskFull bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag IN ('DISK_FULL', 'DISK_LOW', 'LOG_FULL', 'FILE_CANT_GROW'))
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('SUSPENDED', 'NOT_SYNC', 'NOT_HEALTHY')) THEN 1 ELSE 0 END;
DECLARE @hRedoBlk bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag IN ('REDO_BLOCKED', 'REDO_STALLED')) THEN 1 ELSE 0 END;
DECLARE @hLogGenIO bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag = 'LOG_GEN_HIGH')
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('LOG_WRITE_SLOW', 'DATA_READ_SLOW', 'FLOW_CONTROL', 'SYNC_COMMIT_SLOW')) THEN 1 ELSE 0 END;
DECLARE @hRedoIO bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag = 'REDO_Q')
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('DATA_READ_SLOW', 'PAGEIOLATCH', 'MEMORY_LOW')) THEN 1 ELSE 0 END;
DECLARE @hCpu bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag IN ('CPU_PRESSURE', 'THREADPOOL'))
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('REDO_Q', 'SEND_Q', 'LEASE')) THEN 1 ELSE 0 END;
DECLARE @hNet bit = CASE WHEN EXISTS (SELECT 1 FROM @tags WHERE tag IN ('NET_RESENDS', 'CONN_TIMEOUT'))
                               AND EXISTS (SELECT 1 FROM @tags WHERE tag IN ('SEND_Q', 'DISCONNECTED')) THEN 1 ELSE 0 END;

INSERT #f (sev, area, object_name, metric, value, interpretation, next_step, tag)
SELECT v.sev, 'VERDICT', @Server, v.pattern, v.evidence, v.meaning, v.nxt, 'VERDICT'
FROM (VALUES
 (1, N'Storage stall -> cluster/lease -> failover',
     N'IO_STALL/IO_ERROR/LOG_WRITE_SLOW/HEALTH_IO + LEASE/ROLE_CHANGE/STATE_CHANGE',
     N'Storage latency on this node coincided with lease expiry or a role change. Storage stalls freeze SQL and OS threads; lease renewal and sp_server_diagnostics miss their windows and the cluster fails the AG over to the sync secondary.',
     N'Order the TIMELINE: the first storage event before the first lease/state event is the trigger. Get the provider/SAN RCA for that window; consider Azure relaxed thresholds.',
     @hStorage),
 (1, N'Disk full on secondary -> synchronization stopped',
     N'DISK_FULL/DISK_LOW/LOG_FULL/FILE_CANT_GROW + SUSPENDED/NOT_SYNC/NOT_HEALTHY',
     N'A full volume or a file that cannot grow stopped redo/harden; the database suspended and the AG is not healthy. The primary log is now pinned.',
     N'Free/extend space, RESUME data movement, watch the primary log (LOG_PINNED).',
     @hDiskFull),
 (1, N'Redo blocked by readers',
     N'REDO_BLOCKED/REDO_STALLED',
     N'Redo is waiting on locks held by queries on the readable secondary.',
     N'Kill blocker; reschedule DDL/index maintenance; report timeouts.',
     @hRedoBlk),
 (2, N'Heavy log generation + slow secondary IO',
     N'LOG_GEN_HIGH (primary) with LOG_WRITE_SLOW / DATA_READ_SLOW / FLOW_CONTROL / SYNC_COMMIT_SLOW',
     N'Workload burst plus a secondary disk that cannot absorb it: queues grow during the burst and drain slowly after.',
     N'Run this on both replicas (or Invoke-AGDiag.ps1) to see both halves; tune the workload and secondary storage.',
     @hLogGenIO),
 (2, N'IO-bound redo on secondary',
     N'REDO_Q + DATA_READ_SLOW/PAGEIOLATCH/MEMORY_LOW',
     N'Redo is slowed by page reads from a slow data volume or a small buffer pool.',
     N'Memory and data-volume parity with the primary.',
     @hRedoIO),
 (2, N'CPU / worker starvation',
     N'CPU_PRESSURE/THREADPOOL + REDO_Q/SEND_Q/LEASE',
     N'CPU or worker exhaustion is slowing AG work (and can delay lease renewal).',
     N'Find the CPU consumer; Resource Governor for reports.',
     @hCpu),
 (2, N'Network instability',
     N'NET_RESENDS/CONN_TIMEOUT + SEND_Q/DISCONNECTED',
     N'Messages resent or connections timing out while the send queue grows.',
     N'OS report: TCP retransmits, NIC errors, cluster network events.',
     @hNet)
) v(sev, pattern, evidence, meaning, nxt, hit)
WHERE v.hit = 1;

IF NOT EXISTS (SELECT 1 FROM #f WHERE area = 'VERDICT')
    INSERT #f (sev, area, object_name, metric, value, interpretation, next_step, tag)
    SELECT CASE WHEN EXISTS (SELECT 1 FROM #f WHERE sev <= 2) THEN 2 ELSE 4 END,
           'VERDICT', @Server, 'no composite pattern matched',
           CONCAT((SELECT COUNT(*) FROM #f WHERE sev = 1), ' critical, ', (SELECT COUNT(*) FROM #f WHERE sev = 2), ' warning findings'),
           'No known multi-signal pattern on this node alone. Read the individual CRITICAL/WARNING rows, then run on the other replica or use Invoke-AGDiag.ps1 for the cross-node view.',
           NULL, 'VERDICT';

/*-------------------------------------------------------------------------------------
  OUTPUT
-------------------------------------------------------------------------------------*/
SELECT  @Server AS server_name,
        CASE sev WHEN 1 THEN 'CRITICAL' WHEN 2 THEN 'WARNING' WHEN 3 THEN 'INFO' ELSE 'OK' END AS severity,
        area, object_name, metric, value, threshold, interpretation, next_step, tag
FROM #f
WHERE sev <= CASE WHEN @ShowOK = 1 THEN 4 ELSE 3 END
ORDER BY CASE WHEN area = 'VERDICT' THEN 0 ELSE 1 END, sev, area, object_name;

SELECT  @Server AS server_name, event_time, source, event,
        CASE sev WHEN 1 THEN 'CRITICAL' WHEN 2 THEN 'WARNING' ELSE 'INFO' END AS severity,
        tag, detail
FROM #tl
ORDER BY event_time;
