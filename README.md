# SMS Forwarder Web

单管理员、自托管的短信 Webhook 收件箱与限时接码服务。当前可由 iOS 快捷指令自动化取得新短信并发送 JSON POST 请求到后台；中文管理端只保留“看板”“号池”“密钥”和“设置”四个模块。Android 原生客户端尚未实现。

## 核心功能

- Webhook Bearer Token 鉴权和 `delivery_id` 幂等去重
- 支持 iOS 快捷指令最小接入，请求体只需短信正文和接收号码
- Fernet 加密保存号码、发件人、短信正文和验证码
- 通用号池，按当前使用次数最少、ID 最小的顺序原子分配，未达到分配上限的号码可继续使用；管理员可结束当前任务并将号码使用次数重置为 0
- 一次生成 1–200 个密钥，使用或撤销前持续有效，历史列表可直接查看完整密钥
- 密钥历史展示密钥、有效期和“待使用/已使用”状态，“已使用”以红色标签强调；支持按状态筛选并一键复制当前筛选下的全部链接，多个链接使用换行符分隔；只读密钥接口支持按状态和 12/24 小时有效期筛选，也可使用 Webhook Bearer Token
- 首次打开并成功分配号码后开始 12/24 小时倒计时；链接有效期内不限制接收验证码次数，公开领取页只突出显示最新验证码，号码占用保留到链接过期
- 内置短信规则：不限制发件人，提取独立的 4–8 位数字验证码
- 看板以统一的“使用记录”列表分页展示含完整 Key 的领取链接、完整接收手机号、短信摘要和时间；完整正文按需单独读取
- 看板使用记录、号池和密钥列表统一每页显示 20 条，并提供上一页、下一页和当前页码
- 管理员密码使用带随机盐的 scrypt 哈希保存
- 生产依赖固定到已审计版本；应用校验 Host、限制请求体大小，并为管理会话启用 HttpOnly、SameSite 与 HTTPS Secure Cookie
- 容器以非 root、只读根文件系统、无 Linux capabilities 和受限进程数运行；SQLite 主文件及 WAL/SHM 文件限制为仅容器用户可读写
- SQLite 自动版本迁移，短信记录长期加密保存并支持单条删除

号码在任务结束后立即重新进入库存，不设置隔离期。迟到短信可能进入下一次分配窗口，部署者应根据实际风险设置较小的最大分配次数。

## Docker 部署

需要 Docker Engine 24+ 和 Docker Compose v2。

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

将独立随机值写入 `.env` 的 `ADMIN_PASSWORD`、`WEBHOOK_TOKEN` 和 `SESSION_SECRET`，将 Fernet 命令结果写入 `ENCRYPTION_KEY`，再启动：

```bash
docker compose up -d --build
docker compose ps
```

本机测试可使用：

```dotenv
PUBLIC_BASE_URL=http://localhost:8000
COOKIE_SECURE=false
```

打开 `http://localhost:8000`。公网部署必须由 Caddy、Nginx 或云负载均衡器提供 HTTPS，并保持 `COOKIE_SECURE=true`；应用会拒绝 HTTPS 地址配合非安全 Cookie 的配置。不要直接暴露未加密的 8000 端口。

反向代理必须原样传递外部 `Host`，其值要与 `PUBLIC_BASE_URL` 的主机名一致；应用会拒绝其他 Host，防止 Host 头投毒。应用层要求 POST/PUT/PATCH 请求携带 `Content-Length`，拒绝分块传输及超过 64 KiB 的请求体；反向代理也应设置不高于 64 KiB 的请求体上限。

`ADMIN_PASSWORD` 只用于新数据库的首次初始化。凭据写入数据库后，更改该环境变量不会覆盖当前密码。登录后可在“设置”中验证当前密码并修改；修改会提升认证版本、使其他管理会话失效，并为当前会话签发新 Cookie。

忘记密码时，在交互式终端中运行：

```bash
docker compose exec sms-forwarder python -m app.admin reset-password
```

命令会隐藏输入并要求二次确认，不接受命令行密码参数，也不会输出密码。

## 管理流程

1. 在“设置”中选择 12 小时或 24 小时默认有效期；验证码固定使用内置的独立 4–8 位数字规则。
2. 在“号池”中单个录入号码、地区、最大分配次数和启停状态。
3. 在“密钥”中一次生成 1–200 个密钥，并立即复制本次返回的链接。
4. 买家打开链接后自动、幂等地创建接码任务并分配号码；密钥本身不保存号码关联，无库存时保持未使用。
5. iOS 快捷指令在 Webhook 中提供 `message` 和 `recipient`；同一接收号码下仍在有效期内、且匹配全局验证码规则的所有卡密链接都会看到新验证码，新的验证码会覆盖公开页旧验证码。

公开领取页收到验证码后显示醒目的 `NEW` 状态并显示 60 秒倒计时；超过 60 秒后状态切换为“已过期”，验证码区域保持白色背景并继续显示最近一条验证码。链接有效期内不限制接收次数，后续新码会继续覆盖该链接的最新验证码。

分享 Token 位于 URL 查询参数（`/c?t=...`），以提高 Android App 内置浏览器、聊天软件跳转和复制场景的兼容性；公开页仍兼容升级前生成的 Fragment 链接（`/c#t=...`）。公开页交换为短期 HttpOnly 会话后仍保留地址栏中的 Token，便于识别和再次打开完整链接。后续领取和轮询会在存在 URL Token 时继续带 Bearer 头，避免同一浏览器短时间打开多个卡密时被全局 Cookie 会话串页；无 URL Token 时仍可使用已交换的 HttpOnly 会话。数据库保存用于验证的 Token 摘要，以及使用 Fernet 加密的原始 Token；完整值只通过已认证、禁止缓存的管理接口返回，不写入应用日志。由于查询参数可能出现在反向代理或隧道服务访问日志中，部署时不要记录完整 URL 查询串。升级前生成的旧密钥未保存原始值，无法恢复。

## 密钥只读接口

密钥列表和批量复制接口支持管理员登录 Cookie，也支持使用当前 Webhook Bearer Token 做只读鉴权。读取 24 小时未使用卡密：

```text
GET https://你的域名/api/share-links?status=ready&validity_hours=24&limit=100&offset=0
Authorization: Bearer <WEBHOOK_TOKEN>
```

只返回链接列表：

```text
GET https://你的域名/api/share-links/copy?status=ready&validity_hours=24
Authorization: Bearer <WEBHOOK_TOKEN>
```

```json
{
  "content": [
    "https://你的域名/c?t=example-token-1",
    "https://你的域名/c?t=example-token-2"
  ],
  "count": 2
}
```

`status` 可选 `ready` 或 `used`，`validity_hours` 可选 `12` 或 `24`。Webhook Token 可读取完整领取链接，泄露后应立即在管理端轮换。

## Webhook v1

```text
POST https://你的域名/api/webhooks/sms
Authorization: Bearer <WEBHOOK_TOKEN>
Content-Type: application/json
```

首次启动使用 `.env` 中的 `WEBHOOK_TOKEN`。管理员也可在“设置 → Webhook 接入”中生成新 Token；新值只显示一次并支持复制，生成后旧 Token 立即失效，数据库仅保存验证摘要。

```json
{
  "message": "短信正文",
  "recipient": "+8613900000000"
}
```

请求体只要求 `message` 和 `recipient`。服务端会自动生成投递 ID、使用当前 UTC 时间，并将发送方记为 `Webhook`。调用方也可选传 `delivery_id`；同一 ID 重试时返回 `duplicate: true` 且不重复保存。

## iOS 快捷指令接入

公网接入必须先完成 HTTPS 部署，iPhone 中不能使用服务器自己的 `localhost` 地址。不同 iOS 版本的快捷指令名称可能略有差异，基本配置如下：

1. 在“快捷指令 → 自动化”中新建“信息/短信”触发器，只选择确实需要转发的发件人或关键词，并按需要设置为立即运行。
2. 添加“获取 URL 内容”操作，URL 填写管理端“设置 → Webhook 接入”显示的地址，请求方法选择 `POST`。
3. 添加请求头 `Authorization: Bearer <WEBHOOK_TOKEN>` 和 `Content-Type: application/json`。
4. 请求正文选择 JSON，`message` 使用短信触发器提供的“快捷指令输入”，`recipient` 填写该自动化对应的完整接收号码。
5. 用一条不含真实验证码的测试短信验证响应为 `2xx`，然后在管理端看板确认记录。

最小 JSON 与后台接口一致：

```json
{
  "message": "快捷指令输入",
  "recipient": "+8613900000000"
}
```

快捷指令中保存的 Token 属于敏感凭据，不要放入截图、共享快捷指令、普通备忘录或日志。Token 泄露后应立即在管理端重新生成。iOS 是否要求确认、能否在锁屏时自动运行取决于系统版本、触发器和设备设置，应在目标设备上实际测试；本项目不会读取历史短信或直接访问 iOS 短信数据库。

## 数据迁移与安全

数据库位于 Docker 卷 `sms_data`，启动时按版本执行原子迁移。v4 会移除服务表和服务外键；v5 会移除密钥的领取截止时间、号码外键和任务外键；v7 为新密钥增加加密原始值；v10 支持一条短信同步到多个同号码有效任务；v11 会恢复尚未过期但因旧 3 条上限完成的任务；v12 将单链接验证码次数限制为 2，并结束已达到次数的活动任务；v13 调整号码占用统计，使已完成但未过期的链接继续占用号码；v14 解除单链接验证码次数限制，并恢复尚未过期的已完成任务。迁移保留已有短信、号码、密钥、任务和验证码，已创建的任务保持原号码。升级前建议同时安全备份 SQLite 卷与 `ENCRYPTION_KEY`。

`ENCRYPTION_KEY` 丢失后已有加密数据无法恢复，更换密钥也不会自动重加密。不要把 `.env`、数据库或密钥提交到版本库，也不要直接使用 `.env.example` 中的占位值；应用启动时会拒绝这些示例密钥。服务禁用 Uvicorn 访问日志；普通响应和日志不得包含 Token、完整号码、短信正文或验证码。

HTTPS 部署会返回 HSTS；所有页面同时启用 CSP、禁止被嵌入、限制跨源资源与浏览上下文。若同一域名还托管其他不支持 HTTPS 的系统，应在调整 HSTS 策略前先拆分域名。

短信记录默认长期加密保存，不会按保留期自动清理，也不提供一键清空。管理员仍可在短信详情中按需删除单条记录；删除短信时会同步移除依赖该短信的验证码记录。长期运行时应监控 SQLite 卷容量，并将数据库备份视为敏感数据妥善保护。

## 本地开发与测试

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

Docker 测试与构建：

```bash
docker build --target test -t sms-forwarder:test-suite .
docker run --rm sms-forwarder:test-suite
docker compose build
```

开发服务：

```bash
uvicorn app.main:app --reload
```

本项目不接入交易平台订单、支付或自动发货，也不提供批量注册、验证码自动填写或绕过第三方身份验证的能力。部署者必须确保号码来源、使用目的和商品发布符合适用法律及第三方平台规则。
