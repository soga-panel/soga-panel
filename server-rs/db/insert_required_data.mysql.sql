-- =============================================
-- 系统必要数据插入脚本（MariaDB 版）
-- 包含系统正常运行所必需的初始化数据
-- =============================================

-- 插入默认管理员账户（第一个用户自动成为管理员）
INSERT IGNORE INTO users (
  id,
  email,
  username,
  password_hash,
  uuid,
  passwd,
  token,
  is_admin,
  transfer_enable,
  class,
  status
) VALUES (
  1,
  'admin@example.com',
  'admin',
  '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', -- 密码: admin123
  'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  'admin_proxy_password',
  'admin_subscription_token',
  1,
  1099511627776, -- 1TB
  999, -- 最高等级
  1
);

-- 插入系统默认配置
INSERT IGNORE INTO system_configs (`key`, value, description) VALUES
('site_name', '代理面板', '网站名称'),
('site_url', 'https://panel.example.com', '网站地址'),
('docs_url', '', '用户文档地址'),
('register_enabled', '1', '注册开关：0=禁用，1=开放，2=仅限邀请'),
('default_traffic', '10737418240', '默认流量10GB（字节）'),
('default_expire_days', '30', '默认等级到期天数'),
('default_account_expire_days', '3650', '默认账号到期天数（10年）'),
('default_class', '1', '默认用户等级'),
('invite_default_limit', '0', '默认邀请码可使用次数（0表示不限）'),
('traffic_reset_day', '0', '流量重置日（0=不执行每月定时任务，1-31=每月几号）'),
('subscription_url', '', '订阅链接地址（为空时使用默认面板地址）'),
('register_email_verification_enabled', '1', '注册是否需要邮箱验证码（1=开启，0=关闭）'),
('message_queue_page_size', '20', '消息队列每分钟发送分页大小'),
('telegram_bot_token', '', 'Telegram Bot Token（用于公告和流量推送）'),
('telegram_bot_api_base', 'https://api.telegram.org', 'Telegram Bot API 基础地址'),
('telegram_bot_username', '', 'Telegram 机器人用户名（不含@，用于生成一键绑定链接）'),
('telegram_webhook_secret', '', 'Telegram Webhook Secret Token（可选）'),
('telegram_miniapp_url', '', 'Telegram Mini App 打开地址（为空时自动使用 site_url）'),
('rebate_rate', '0', '邀请返利比例（0-1之间，例如0.1表示10%）'),
('rebate_mode', 'every_order', '返利模式：first_order（首单）或 every_order（循环）'),
('rebate_withdraw_fee_rate', '0.05', '返利提现手续费比例（0-1之间，例如0.05=5%）'),
('rebate_withdraw_min_amount', '200', '返利提现最低金额（元）');

-- 插入默认审计规则
INSERT IGNORE INTO audit_rules (name, rule, description) VALUES
('种子下载', 'regexp:.*\\.torrent', '种子文件'),
('成人内容', 'regexp:.*porn.*', '成人内容');

-- 插入默认白名单
INSERT IGNORE INTO white_list (rule, description) VALUES
('domain:api.telegram.org', 'Telegram API'),
('geoip:cn', '中国IP段'),
('port:80,443', '常用端口');

-- 插入欢迎公告
INSERT IGNORE INTO announcements (
  title,
  content,
  type,
  is_active,
  is_pinned,
  priority,
  created_by,
  created_at,
  updated_at
) VALUES
(
  '欢迎使用 Soga Panel',
  '欢迎使用我们的轻量级代理面板服务！

## 功能特点

- **高性能**: 基于 Cloudflare Workers 架构
- **易管理**: 直观的用户界面
- **多协议**: 支持多种代理协议
- **实时监控**: 流量使用情况实时显示

## 使用指南

1. 查看您的节点列表
2. 获取订阅链接
3. 在客户端中配置使用
4. 定期检查流量使用情况

如有问题，请联系管理员。',
  'notice',
  1,
  1,
  100,
  1,
  UNIX_TIMESTAMP(),
  UNIX_TIMESTAMP()
),
(
  '系统维护通知',
  '为了提供更好的服务，我们将在以下时间进行系统维护：

**维护时间**: 2025年05月51日 05:00 - 20:00 (UTC+8)

**影响范围**: 
- 面板访问可能短暂中断
- 代理服务正常运行

维护完成后将提供更稳定的服务体验。

感谢您的理解与支持！',
  'warning',
  1,
  0,
  50,
  1,
  UNIX_TIMESTAMP(),
  UNIX_TIMESTAMP()
);

-- 插入示例节点数据（基础节点配置）
INSERT IGNORE INTO nodes (
  id,
  name,
  type,
  node_class,
  node_config
) VALUES
-- Shadowsocks 节点
(1, 'ss-tcp', 'ss', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30001,"cipher":"aes-128-gcm","obfs":"plain","path":"/path","host":"www.server.com"},"client":{"server":"example.com","port":30001}}'),
(2, 'ss2022-aes128', 'ss', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30002,"cipher":"2022-blake3-aes-128-gcm","password":"o5DWBXipV4BgFk11m6PiMg==","obfs":"plain"},"client":{"server":"example.com","port":30002}}'),
(3, 'ss2022-aes256', 'ss', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30003,"cipher":"2022-blake3-aes-256-gcm","password":"VJ96gVvktH8ZcTsSHo4at9Ef8lavE/dW/WL1kRAoIlE=","obfs":"plain"},"client":{"server":"example.com","port":30003}}'),

-- ShadowsocksR 节点
(4, 'ssr-tcp', 'ssr', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30004,"method":"chacha20-ietf","protocol":"auth_aes128_sha1","obfs":"plain","single_port_type":"protocol"},"client":{"server":"example.com","port":30004}}'),
-- V2Ray VMess 节点
(5, 'vmess-tcp', 'v2ray', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30005,"stream_type":"tcp","tls_type":"none"},"client":{"server":"example.com","port":30005}}'),
(6, 'vmess-tcp-tls', 'v2ray', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30006,"stream_type":"tcp","tls_type":"tls"},"client":{"server":"example.com","port":30006,"tls_host":"example.com"}}'),
(7, 'vmess-ws', 'v2ray', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30007,"stream_type":"ws","tls_type":"none","path":"/112233"},"client":{"server":"example.com","port":30007}}'),
(8, 'vmess-ws-tls', 'v2ray', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30008,"stream_type":"ws","tls_type":"tls","path":"/112233"},"client":{"server":"example.com","port":30008,"tls_host":"example.com"}}'),

-- VLESS 节点
(9, 'vless-tcp-tls', 'vless', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30009,"stream_type":"tcp","tls_type":"tls"},"client":{"server":"example.com","port":30009,"tls_host":"example.com"}}'),
(10, 'vless-ws-tls', 'vless', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30010,"stream_type":"ws","tls_type":"tls","path":"/112233"},"client":{"server":"example.com","port":30010,"tls_host":"example.com"}}'),

-- Trojan 节点
(11, 'trojan-tcp-tls', 'trojan', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30011,"stream_type":"tcp","tls_type":"tls"},"client":{"server":"example.com","port":30011,"tls_host":"example.com"}}'),
(12, 'trojan-ws-tls', 'trojan', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30012,"stream_type":"ws","tls_type":"tls","path":"/112233"},"client":{"server":"example.com","port":30012,"tls_host":"example.com"}}'),

-- Hysteria 节点
(13, 'hysteria', 'hysteria', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30013,"obfs":"salamander","obfs_password":"","up_mbps":1000,"down_mbps":1000},"client":{"server":"example.com","port":30013}}'),

-- AnyTLS 节点
(14, 'anytls', 'anytls', 1, '{"basic":{"pull_interval":60,"push_interval":60,"speed_limit":0},"config":{"port":30014,"padding_scheme":["stop=8","0=30-30","1=100-400","2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000","3=9-9,500-1000","4=500-1000","5=500-1000","6=500-1000","7=500-1000"]},"client":{"server":"example.com","port":30014}}');

-- 验证必要数据插入（非必须，可在导入后运行检查）
-- SELECT 'Required data inserted successfully' as status;
-- SELECT CONCAT('Admin user created: ', email) as admin FROM users WHERE id = 1;
-- SELECT CONCAT('System configs count: ', COUNT(*)) as configs FROM system_configs;
-- SELECT CONCAT('Nodes count: ', COUNT(*)) as nodes FROM nodes;
-- SELECT CONCAT('Announcements count: ', COUNT(*)) as announcements FROM announcements;
