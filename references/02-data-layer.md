# 02 · 数据获取层

> 模块名沿用 `wechat-wcdb-local-extract`。**本 skill 已内嵌此层的完整方法，不需要另装外部 skill。**
>
> 本篇给的是路径、参数、坑与**最小验证片段**。完整实现由执行本 skill 的 AI 依本文档完成。

四步链：**定位目录 → 提取密钥 → 选择性解密 → 提取消息**。每步做完都要过验证再往下走。

适用前提：Windows + 微信桌面版 4.x，且目标账号在本机登录过（见 SKILL.md Q1 / Q2）。

---

## 本层的操作边界（可直接对用户说明）

以下五条是实际的技术事实，不是承诺性话术：

| 边界 | 成立 | 依据 |
|---|---|---|
| 不注入任何代码 | 是 | 全程只调用 `ReadProcessMemory` 读取；没有写内存、没有远程线程、没有 DLL 注入 |
| 不附加调试器 | 是 | 进程句柄用 `OpenProcess(PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION)` 获取，这两个都是普通查询权限，不涉及调试权限 |
| 不修改微信的文件 | 是 | 对微信目录只读；所有产物（密钥文件、解密结果）写在自己的工作目录 |
| 不发任何网络请求 | 是 | 本层全程离线，代码中没有网络调用 |
| 只在本机作业 | 是 | 只对 `Weixin.exe` 进程操作，不触碰其他应用 |

**关于「只读自己账号」要说准确**，这里有个容易被含糊过去的地方：

- **扫描范围**：遍历的是微信进程的可读内存空间（不止密钥那一处）；
- **提取范围**：只取「密钥标记字符串之后的至多 1024 字节」这一小段。

两者不是一回事，别对外说成「只扫描了自己账号的内存」。准确说法是：
**只对微信进程操作，且只提取密钥相关的那一小段；取到的是当前登录账号的密钥。**

**由此推出一条硬前提**：数据库密钥只存在于微信进程内存中，所以
**提取密钥时，微信必须处于登录运行状态，且登录的正是目标账号**。
密钥取到后可以缓存复用，此后的解密不再需要微信在线。

---

## 第 1 步：定位数据目录与账号

### 目标

拿到两样东西：**微信数据根目录**与**目标账号 wxid**。

### 原理

微信桌面版的数据库位置记在配置 ini 里，不靠猜。配置目录：

```
%APPDATA%\Tencent\xwechat\config\*.ini
```

该 ini 的**第一行**就是数据根。根目录下每个已登录过的账号各占一个子目录，形如
`<根>\<wxid>_<4位后缀>\db_storage`。目录名去掉 `_<4位后缀>` 即为该账号的 wxid
（另有少数账号目录名本身就带完整 wxid，按实际为准）。

### 关键步骤

1. 读 `%APPDATA%\Tencent\xwechat\config\` 下的 ini，取第一行作为数据根；
2. 列出根下所有 `<wxid>_<后缀>` 形式的目录，作为**候选账号**；
3. 若有多个候选，**停下来问用户用哪个**，不要自选（见 SKILL.md Q2）；
4. 目标账号的库目录 = `<根>\<账号目录>\db_storage`。

### 最小验证片段

```python
import os, glob

root = open(glob.glob(os.path.expandvars(
    r"%APPDATA%\Tencent\xwechat\config\*.ini"))[0], encoding="utf-8").readline().strip()
print("数据根:", root)

accounts = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
for a in accounts:
    db = os.path.join(root, a, "db_storage")
    print(f"账号目录 {a} | db_storage 存在: {os.path.isdir(db)}")
```

判读标准：能列出账号目录、且目标账号下 `db_storage` 存在，本步通过。
列不出账号，多半是微信没在这台机器登录过，回到 Q2 处理。

### 坑

- ini 文件可能有多个，取**第一行有内容**的那个，不要取文件名排序第一个。
- 账号目录名与 wxid 的关系要实际核对，不要硬编码后缀长度。
- 不要写真实 wxid 进任何交付物。

---

## 第 2 步：提取数据库密钥

### 目标

为每个库拿到它的 **32 字节 enc_key**。

### 原理

微信 4.x 用 SQLCipher4 变体加密库。密钥不在磁盘上，只在**微信进程内存**里
（微信启动时解密 Config 得到）。所以要读进程内存。

**硬前提**：提取时必须让微信**处于登录运行状态，且登录的是目标账号**。
密钥取到后缓存复用，之后解密不再需要微信在线。
只读、不注入、不调试的完整说明见开篇「本层的操作边界」。

内存里的密文是一段 blob，前面有标记字符串定位：

```
com.Tencent.WCDB.Config.Cipher
```

blob 拿回来后**先做一次 XOR 掩码解码**（掩码是固定常量，见下），
解码结果里能正则匹配到 `x'<64~192位hex>'` 形式的字面量，这就是候选密钥材料。

掩码常量（来源：开源实现 `wcdb-key-tool`，已多次验证）：

```python
WINDOWS_CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24")
```

### 关键步骤

1. 定位微信进程（`Weixin.exe`），枚举其可读内存区（跳过用户态地址上限以上的部分）；
2. 在每个区里搜 `com.Tencent.WCDB.Config.Cipher`，取其后**最多 1024 字节**作为 blob；
3. blob 做 XOR 掩码解码（循环用掩码异或）；
4. 解码结果按 `[xX]'([0-9a-fA-F]{64,192})'` 提取 hex 字面量，**按 64 位 hex 窗口切片**得到候选；
5. 每个候选按两种方式派生，再校验：
   - **DIRECT**：候选本身就是 enc_key；
   - **PBKDF2**：候选是 passphrase，需配合对应 salt 迭代派生。
6. 校验方式见下方片段；命中即记下该库的 `{enc_key, salt}`。

**加速要点（重要，不做会慢到不可用）**：blob 里通常同时存在
「32 字节派生产物 + 紧随其后的 16 字节 salt」这一对。用它**定向**做 PBKDF2，
能把派生次数从「候选数 × 迭代数」降到「候选数 × 1」。
本机实测从数分钟降到约 4 秒。

### 最小验证片段

拿去校验任何一个候选密钥是否正确（`page1` 为该库文件的**前 4096 字节**）：

```python
import hashlib, hmac as hmac_mod, struct

def verify_key(enc_key: bytes, page1: bytes) -> bool:
    """SQLCipher4 规范：比对第 1 页尾部的 HMAC。"""
    salt = page1[:16]
    mac_key = hashlib.pbkdf2_hmac(
        "sha512", enc_key, bytes(b ^ 0x3A for b in salt), 2, dklen=32)
    data = page1[16:4096 - 80 + 16]
    h = hmac_mod.new(mac_key, data, hashlib.sha512)
    h.update(struct.pack("<I", 1))
    return h.digest() == page1[4096 - 64:4096]

page1 = open(r"<db_storage>\message\message_0.db", "rb").read(4096)
print(verify_key(bytes.fromhex("<你的候选密钥>"), page1))
```

判读标准：返回 `True` 即密钥正确。返回 `False` 说明候选不对，换下一个，不要硬试解密。

**整库级别的复核**：不同库的密钥不同；同一个密钥对多个库都返回 `True` 是不可能的，
出现这种情况说明校验逻辑写错了。

### 坑

- **不要暴力全派生**。25 个库 × 25 个候选 × 迭代，会跑到几百秒。先做定向。
- 简化版提取脚本（直接扫内存不做 XOR 解码）会直接失败。
- 库数可能有 25 个以上、总体积上 TB，**不要尝试全量扫描解密**。
- 微信升级（4.1.x → 4.2.x）可能改 Config 格式，届时掩码与正则都要重验。

---

## 第 3 步：选择性解密

### 目标

把需要的库解成明文可读的 SQLite 文件。

### 原理

SQLCipher 是**页级加密**：整库按 4096 字节分页，每页独立解密。
所以可以只解要用的库，不必碰其余上 TB 的数据。

常规需要的六个库：

```
message/message_0.db  ~  message_3.db     消息主体（分片存放）
contact/contact.db                        联系人、群成员、标签
session/session.db                        会话列表与最后一条消息
```

解密一页的顺序：**先解 IV 与内容，再剥掉尾部保留区**。保留区结构：

```
每页 = 内容 | IV(16) | HMAC(64)      尾部保留 80 字节
```

即解出的明文要把每页最后 80 字节去掉，拼起来才是合法 SQLite 文件；
同时文件头要还原成 `SQLite format 3\x00`。

**WAL 补丁**：主库解完之后，若同名 `-wal` 存在，还要按同样的页规则解 WAL 帧
并合并，否则会漏掉迁移后尚未 checkpoint 的记录。WAL 帧头校验用 magic `0x377F0682`。

### 关键步骤

1. 按需解密六个目标库，输出到自己的工作目录（不要写进微信目录）；
2. 每解完一个库，若源目录存在同名 `-wal`，做 WAL 补丁；
3. 已解出的库若已存在且非空，跳过（除非用户要求重解）。

### 最小验证片段

```python
import sqlite3

p = r"<你的输出目录>\message\message_0.db"
with open(p, "rb") as f:
    print("文件头:", f.read(16))          # 应为 b'SQLite format 3\x00'

con = sqlite3.connect(p)
print("表数量:", con.execute(
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0])
```

判读标准：文件头正确、能读出表数量，本步通过。
文件头不对说明密钥错或保留区没剥干净。

### 坑

- 保留区大小记错（写成 64 或 96）会导致页面整体错位，表现为「能连上但读不出表」。
- WAL 里通常是 0 个有效帧（已 checkpoint 进主库），**先校验帧头再决定是否补丁**，
  不要无条件合并。
- 解密产物可能很大，不要放系统临时目录（会被清理，重跑代价高）。

---

## 第 4 步：消息提取

### 目标

把消息从库里读出来，变成能用的结构化数据。

### 原理与关键步骤

**① 消息表按会话散列命名**。表名规则：

```python
tname = "Msg_" + hashlib.md5(username.encode()).hexdigest()
```

**② 内容字段可能是 zstd 压缩**。`message_content` / `compress_content`
读出来若是 bytes 且以 `28 B5 2F FD` 开头，就是 zstd，须解压后再按文本处理。
**连库时必须设 `text_factory = bytes`**，让驱动别自作主张按 UTF-8 解码，
否则压缩数据会在解码这一步就变成乱码。

```python
con = sqlite3.connect(path)
con.text_factory = bytes
```

**③ `local_type` 取低 32 位**。该字段高位是子类型标志位，直接当类型用会得出一堆怪值。

```python
raw = 244813135921          # 0x3900000031
local_type = raw & 0xFFFFFFFF   # → 49，应用消息
```

**④ `real_sender_id` 是每个 `message_N.db` 独立的本地索引**，库内没有映射表。
可靠的反推办法：全库扫文本消息，凡内容以 `wxid_xxx:\n` 开头的，
把前缀里的 wxid 与 `real_sender_id` 建立映射，逐步累积成对照表。

**⑤ 群聊里自己发的消息没有 `wxid_xxx:\n` 前缀**。
即：无前缀 + 查不到映射 = 本人所发。

### 最小验证片段

```python
import sqlite3, hashlib

con = sqlite3.connect(r"<你的输出目录>\message\message_0.db")
con.text_factory = bytes
t = "Msg_" + hashlib.md5(b"<某个会话的username>").hexdigest()
rows = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()
print("该会话消息数:", rows[0])
```

判读标准：能数出消息条数即通过。条数为 0 要区分两种情况——
会话确实没消息，或表名算错了（username 大小写、前后空格都会导致算错）。

### 坑

- `text_factory` 忘了设，压缩内容直接变乱码，且**看不出是压缩导致的**。
- `local_type` 不取低 32 位，会得到 `244813135921` 这种数，永远匹配不上任何类型。
- 表名用的 username 必须与库中 `session` 表里存的完全一致，别自己拼。
- 别把「没查到前缀」直接判成本人发言，要先确认映射表已经建全。

---

## 完成标志

四步都过验证后，你手上应有：明文的 message / contact / session 库，
以及一份能按会话读取消息的代码。这就是后续所有功能的数据底座。

媒体（图片 / 表情 / 视频 / 文件 / 视频号）不在本篇，见 `03-media-layer.md`。

## 与上层业务的接口约定

- **只读**：全程对微信目录不做任何修改，只读副本、只写自己的输出目录；
- **单一真相源**：数据目录、账号、时间范围写进一个配置文件，禁止各处硬编码；
- **可重跑**：解密产物已存在时跳过，避免每次重来。
