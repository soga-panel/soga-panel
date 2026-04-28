# 后端概览

后端基于 **Cloudflare Workers + D1** 构建，兼容 Soga v1 WebAPI，提供用户、管理员、订阅等接口。

## 目录结构

```
worker/
├── db/                     # 数据库脚本与示例数据
├── src/
│   ├── api/                # 业务接口（auth、admin、user、soga 等）
│   ├── middleware/         # 中间件（认证、API Key 等）
│   ├── services/           # 数据库、缓存、调度、日志等服务
│   ├── utils/              # 通用工具
│   └── handler.ts          # 路由分发
├── index.ts                # Worker 入口
├── package.json            # 依赖管理
└── wrangler*.toml          # Wrangler 配置
```

## 环境准备

1. Node.js ≥ 22（用于本地安装依赖、运行脚本）
2. 已登录的 Cloudflare 账号
3. Wrangler CLI（建议全局安装 `npm i -g wrangler`）

## 安装依赖

```bash
cd worker
pnpm install
```

## 创建与绑定 D1 数据库

```bash
# 创建数据库
wrangler d1 create soga-panel-d1

# 记录返回的 database_id，并写入 wrangler.toml
```

`wrangler.toml` 关键配置示例：

```toml
name = "soga-panel-backend"
main = "index.ts"
compatibility_date = "2024-05-13"
account_id = "your-account-id"

[vars]
JWT_SECRET = "your-secure-secret"
WEBAPI_KEY = "your-soga-api-key"
TWO_FACTOR_SECRET_KEY = "your-2fa-encryption-secret"

[[d1_databases]]
binding = "DB"
database_name = "soga-panel-d1"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## 数据库初始化

```bash
wrangler d1 execute soga-panel-d1 --file=./db/db.sql --remote
wrangler d1 execute soga-panel-d1 --file=./db/insert_required_data.sql --remote
# 可选：导入示例套餐数据
wrangler d1 execute soga-panel-d1 --file=./db/insert_package_data.sql --remote
```

## 开发与部署

```bash
# 本地调试
wrangler dev

# 生产部署
wrangler deploy
```

部署成功后，可访问 `https://your-worker.workers.dev/api/health` 验证服务状态。

## 主要环境变量

| 变量名 | 说明 |
| --- | --- |
| `JWT_SECRET` | JWT 签名密钥 |
| `WEBAPI_KEY` | Soga WebAPI 密钥（与节点配置一致） |
| `TWO_FACTOR_SECRET_KEY` | 二步验证密钥加密用对称密钥（不配置则回退到 `JWT_SECRET`） |
| `MAIL_PROVIDER` | `none` / `resend` / `smtp` / `sendgrid` |
| `MAIL_FROM` | 发件邮箱地址 |
| `RESEND_API_KEY` | 使用 Resend 时必填 |
| 其他 `MAIL_*` / `SMTP_*` | 邮件驱动所需配置 |

## 常用调试命令

```bash
# 查看实时日志
wrangler tail

# 执行 SQL 查询
wrangler d1 execute soga-panel-d1 --command="SELECT * FROM users LIMIT 5" --remote

# 触发计划任务或 API
curl https://your-worker.workers.dev/api/admin/traffic/overview -H "Authorization: Bearer <token>"
```

## telegram bot webhook
```
curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{
    "url":"https://你的面板域名/api/telegram/webhook",
    "secret_token":"<telegram_webhook_secret>"
  }'
```

## Telegram Mini App（在 Bot 内打开面板）

1. 在系统配置中设置 `telegram_miniapp_url`（可选，不填则默认使用 `site_url`）。
2. Bot 已支持 `/panel` 命令，会返回一个 `web_app` 按钮，点击后在 Telegram 内打开面板。
3. 推荐将菜单按钮指向 Mini App 登录页：

```bash
curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setChatMenuButton" \
  -H "Content-Type: application/json" \
  -d '{
    "menu_button": {
      "type": "web_app",
      "text": "打开面板",
      "web_app": { "url": "https://你的面板域名/auth/login?tgMiniApp=1" }
    }
  }'
```

4. 可选：设置机器人命令列表（包含 `/panel`）：

```bash
curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setMyCommands" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      {"command":"help","description":"查看帮助"},
      {"command":"register","description":"注册新账号"},
      {"command":"code","description":"提交邮箱验证码"},
      {"command":"info","description":"查看账号信息"},
      {"command":"link","description":"获取订阅链接"},
      {"command":"panel","description":"在 Telegram 内打开面板"}
    ]
  }'
```

5. Telegram 内注册流程（未绑定账号时）：

```text
/register
  -> Bot 返回人机验证码
  -> 用户点击 4 选 1 验证码按钮（1 个正确，3 个错误）
  -> 验证通过后依次发送：邮箱、用户名、邀请码（可发送 skip / 无 跳过）
  -> 邮箱收到 6 位验证码后，直接发送 6 位数字验证码
  -> 注册成功后 Bot 返回初始账号信息，并自动绑定当前 Telegram
```

## 安全建议

- 使用强密码或随机字符串作为 `JWT_SECRET`、`WEBAPI_KEY`
- 对生产数据库定期备份
- 监控 Worker 日志与 Cloudflare 网络分析，及时发现异常流量
- 在管理后台登录后及时修改默认管理员密码

更多接口详情见《backend-api.md》。
