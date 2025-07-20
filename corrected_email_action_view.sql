-- =====================================
-- E4: 邮件动作视图 - 高性能预计算方案（修正版）
-- 使用 AggregatingMergeTree + Materialized View 实现最佳性能
-- =====================================

-- 1. 创建存储最新状态的聚合表（修正版）
CREATE TABLE IF NOT EXISTS m01.latest_action_status
(
    mail_id UInt64,
    -- 修正：argMax的正确语法格式
    latest_action AggregateFunction(argMax, String, DateTime64(3)),
    latest_reason AggregateFunction(argMax, String, DateTime64(3)),
    action_count AggregateFunction(count),
    action_history AggregateFunction(groupArray, Tuple(
        String,                     -- message_type
        DateTime64(3),             -- log_timestamp  
        String,                    -- old_status
        String,                    -- new_status
        DateTime64(3),             -- status_changed_at
        String,                    -- reason
        String,                    -- triggered_by
        UInt64,                    -- processing_duration_ms
        String,                    -- additional_data
        DateTime64(3)              -- created_at
    ))
) ENGINE = AggregatingMergeTree()
ORDER BY mail_id
-- 改进：添加合适的分区策略，便于数据管理
PARTITION BY toYYYYMM(toDateTime(mail_id / 1000000000))  -- 假设mail_id包含时间戳信息
SETTINGS index_granularity = 8192,
         -- 性能优化设置
         merge_with_ttl_timeout = 86400,
         merge_with_recompression_ttl_timeout = 86400;

-- 2. 创建Materialized View自动维护聚合表（修正版）
CREATE MATERIALIZED VIEW IF NOT EXISTS m01.mv_latest_action_status 
TO m01.latest_action_status AS
SELECT 
    mail_id,
    -- 修正：确保DateTime64时区一致性
    argMaxState(new_status, toDateTime64(status_changed_at, 3)) AS latest_action,
    argMaxState(reason, toDateTime64(status_changed_at, 3)) AS latest_reason,
    countState(*) AS action_count,
    groupArrayState((
        CAST(coalesce(message_type, ''), 'String'),
        toDateTime64(log_timestamp, 3),
        CAST(coalesce(old_status, ''), 'String'),
        CAST(coalesce(new_status, ''), 'String'),
        toDateTime64(status_changed_at, 3),
        CAST(coalesce(reason, ''), 'String'),
        CAST(coalesce(triggered_by, ''), 'String'),
        CAST(coalesce(processing_duration_ms, 0), 'UInt64'),
        CAST(coalesce(additional_data, ''), 'String'),
        toDateTime64(created_at, 3)
    )) AS action_history
FROM m01.data_action  -- 确保表名正确
GROUP BY mail_id;

-- 3. 主视图：高性能的邮件动作最终视图（优化版）
CREATE OR REPLACE VIEW m01.data_action_final_view AS
SELECT 
    miv.id,
    -- 修正：按时间戳正确排序动作历史
    arraySort(x -> x.5, las.action_history) AS action_history,
    las.action_count,
    las.latest_action,
    las.latest_reason,
    
    -- mail_integrated_view的所有字段
    miv.timestamp,
    miv.send_time,
    miv.subject,
    miv.message_id,
    miv.bcc_name,
    miv.bcc_email,
    miv.bcc_email_account,
    miv.bcc_email_domain,
    miv.display_from_name,
    miv.display_from_address,
    miv.display_from_account,
    miv.display_from_domain,
    miv.display_to_name,
    miv.display_to_address,
    miv.display_to_account,
    miv.display_to_domain,
    miv.config,
    miv.sasl_login,
    miv.sasl_method,
    miv.client_ip,
    miv.client_ptr,
    miv.client_port,
    miv.client_helo,
    miv.client_active_connections,
    miv.client_envelope_from_address,
    miv.client_envelope_from_account,
    miv.client_envelope_from_domain,
    miv.client_envelope_to_name,
    miv.client_envelope_to_address,
    miv.client_envelope_to_account,
    miv.client_envelope_to_domain,
    miv.tls,
    miv.server,
    miv.protocol_version,
    miv.text_body,
    miv.html_body,
    miv.deconstruction_modules,
    miv.detection_modules,
    miv.hash_sha1,
    miv.hash_sha256,
    miv.hash_md5,
    miv.direction,
    miv.protocol_check,
    miv.extract_password,
    miv.eml_file_path,
    miv.classification,
    miv.eml_size_bytes,
    miv.urls,
    miv.files,
    miv.headers,
    miv.qrcodes,
    miv.yara_rules,
    miv.expr_rules,
    miv.antivirus_rules,
    miv.action_rules,
    miv.intelligence_rules,
    miv.matchmail_rules,
    miv.ai_detection,
    miv.ai_classification,
    miv.ai_scan_time_us,
    miv.module_logs,
    miv.url_count,
    miv.file_count,
    miv.header_count,
    miv.qrcode_count,
    miv.yara_rules_count,
    miv.expr_rules_count,
    miv.action_rules_count,
    miv.intelligence_rules_count,
    miv.matchmail_rules_count,
    miv.clamav_scan_count,
    miv.rising_antivirus_count,
    miv.unique_url_domains,
    miv.unique_file_extensions,
    miv.unique_header_names,
    miv.unique_custom_header_names,
    miv.unique_yara_rules,
    miv.unique_expr_rules,
    miv.unique_intelligence_types,
    miv.matchmail_unique_attributes

FROM m01.mail_integrated_view AS miv
LEFT JOIN (
    -- 优化：使用更高效的聚合查询
    SELECT 
        mail_id,
        argMaxMerge(latest_action) AS latest_action,
        argMaxMerge(latest_reason) AS latest_reason,
        countMerge(action_count) AS action_count,
        groupArrayMerge(action_history) AS action_history
    FROM m01.latest_action_status
    GROUP BY mail_id
    -- 性能优化：添加SETTINGS
    SETTINGS max_threads = 4
) AS las ON miv.id = las.mail_id;

-- =====================================
-- 性能优化：索引和分区策略
-- =====================================

-- 为 data_action 表添加复合索引
ALTER TABLE m01.data_action ADD INDEX IF NOT EXISTS idx_mail_status_time 
    (mail_id, status_changed_at) TYPE minmax GRANULARITY 1;

-- 添加跳数索引以提升过滤性能
ALTER TABLE m01.data_action ADD INDEX IF NOT EXISTS idx_new_status 
    new_status TYPE set(100) GRANULARITY 1;

-- 为主表添加必要索引（如果不存在）
-- ALTER TABLE m01.mail_integrated_view ADD INDEX IF NOT EXISTS idx_timestamp 
--     timestamp TYPE minmax GRANULARITY 1;

-- =====================================
-- 数据质量检查和监控
-- =====================================

-- 检查聚合表数据一致性
CREATE VIEW IF NOT EXISTS m01.data_quality_check AS
SELECT 
    'action_aggregation' as check_type,
    count() as total_records,
    uniqExact(mail_id) as unique_mails,
    min(countMerge(action_count)) as min_actions_per_mail,
    max(countMerge(action_count)) as max_actions_per_mail,
    avg(countMerge(action_count)) as avg_actions_per_mail
FROM m01.latest_action_status;

-- =====================================
-- 维护和优化命令
-- =====================================

-- 查看聚合表状态和大小
-- SELECT 
--     count() as row_count,
--     uniqExact(mail_id) as unique_mail_count,
--     formatReadableSize(sum(data_compressed_bytes)) as compressed_size,
--     formatReadableSize(sum(data_uncompressed_bytes)) as uncompressed_size,
--     round(sum(data_compressed_bytes) / sum(data_uncompressed_bytes), 4) as compression_ratio
-- FROM system.parts 
-- WHERE table = 'latest_action_status' AND database = 'm01' AND active = 1;

-- 检查Materialized View状态
-- SELECT 
--     database, table, engine, 
--     formatReadableSize(total_bytes) as size,
--     total_rows
-- FROM system.tables 
-- WHERE database = 'm01' AND name LIKE '%action%';

-- 强制优化聚合表（生产环境慎用）
-- OPTIMIZE TABLE m01.latest_action_status FINAL;

-- 重建聚合表（数据结构变化时）
-- DROP TABLE IF EXISTS m01.latest_action_status;
-- DROP VIEW IF EXISTS m01.mv_latest_action_status;
-- 然后重新创建表和视图

-- =====================================
-- 高性能查询示例
-- =====================================

-- 示例1：邮件列表查询（优化版）
-- SELECT 
--     id,
--     subject,
--     latest_action,
--     latest_reason,
--     action_count,
--     timestamp,
--     send_time,
--     arrayElement(display_from_address, 1) as from_addr,
--     arrayElement(display_to_address, 1) as to_addr,
--     -- 显示最近的动作时间
--     arrayElement(action_history, -1).5 as last_action_time
-- FROM m01.data_action_final_view
-- WHERE timestamp >= subtractDays(now(), 7)
--   AND latest_action IN ('已放行', '已拦截', '待检测')
-- ORDER BY timestamp DESC
-- LIMIT 20 OFFSET 0
-- SETTINGS max_threads = 2, max_memory_usage = 1000000000;

-- 示例2：状态统计查询（带时间段分析）
-- SELECT 
--     latest_action,
--     count() as mail_count,
--     round(avg(action_count), 2) as avg_actions_per_mail,
--     round(countIf(action_count > 1) / count() * 100, 2) as multi_action_rate_percent
-- FROM m01.data_action_final_view
-- WHERE timestamp >= subtractDays(now(), 1)
-- GROUP BY latest_action
-- ORDER BY mail_count DESC;

-- 示例3：动作历史详细分析
-- SELECT 
--     id,
--     subject,
--     arrayMap(x -> (x.4, x.5, x.6), action_history) as status_timeline
-- FROM m01.data_action_final_view
-- WHERE id = 12345  -- 特定邮件ID
-- AND action_count > 1;