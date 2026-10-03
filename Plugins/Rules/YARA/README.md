# YARA 规则目录（默认空 —— 规则请自行拉取）

**本目录不含任何 YARA 规则文件，这是有意的。**

ZETA 的 YARA 检测依赖社区规则，而主流规则集的许可不适合随本仓库分发；
同时社区规则若不加筛选直接启用，会让 ZETA 退化成弹窗机（原因见下）。
因此本仓库只提供**加载机制**，不提供规则内容。

## 一、去哪拉

| 上游 | 许可 | 取哪个子目录 |
|---|---|---|
| <https://github.com/Yara-Rules/rules> | GPL-2.0（传染性 copyleft） | `rules/`（排除 `deprecated/`、`.github/`） |
| <https://github.com/bartblaze/Yara-rules> | MIT | `Yara-rules/` |
| <https://github.com/Neo23x0/signature-base> | DRL 1.1（商业使用需另行授权） | `signature-base/` |

```powershell
$tmp = "$env:TEMP\zeta-yara-upstream"
$dst = "E:\远控\zeta\Plugins\Rules\YARA\community"    # ← 改成你的实际路径
New-Item -ItemType Directory -Path $tmp,$dst -Force | Out-Null

git clone --depth 1 https://github.com/Yara-Rules/rules "$tmp\yara-rules"
robocopy "$tmp\yara-rules\rules" "$dst\10-GPL2-yara-rules" /E /XD deprecated .github

git clone --depth 1 https://github.com/bartblaze/Yara-rules "$tmp\bartblaze"
robocopy "$tmp\bartblaze\Yara-rules" "$dst\00-MIT-bartblaze" /E

git clone --depth 1 https://github.com/Neo23x0/signature-base "$tmp\signature-base"
robocopy "$tmp\signature-base\signature-base" "$dst\20-DRL1.1-signature-base" /E
```

直连 GitHub 失败时给 URL 加代理前缀，例如
`https://gh-proxy.com/https://github.com/Yara-Rules/rules`。
也可以用同级 `tools/fetch-community-rules.ps1` 一键完成。

## 二、放哪 —— 不用改配置

引擎按 `../Rules_EDR.json` 的 `Rule_Yara_Paths = YARA\*.yar` **递归**收集规则：
放进 `community/` 下任意子目录都会被加载。目录为空时引擎不会报错，
只是"没有规则可匹配"，扫描结果统一为干净。

## 三、拉完必读：直接全量启用会变成弹窗机

实测结论（不是推测）：

> ZETA 的判定是「**任意一条 YARA 规则命中 → 自动扫描 +100 分 → 直接越过告警阈值 85**」。

而社区规则集是给分析人员**逐条人工研判**用的，其中大量规则描述的是"程序具有某种能力"，
而非"这是恶意软件"：

| 这类规则 | 真实含义 | 在真实机器上的后果 |
|---|---|---|
| `IsPE64` / `IsPE32` / `IsDLL` | 只要是个 PE | 命中几乎所有程序 |
| `with_urls` / `with_sqlite` | 程序里含 URL / 内嵌 SQLite | 命中 git、bun、node |
| `Chacha_256_constant` / `DES_Long` | 含加密常量 | 命中任何用 OpenSSL/Chromium/Qt 的软件 |
| `QtFrameWork` / `Microsoft_Visual_Cpp_8` | 用某框架/编译器编译 | 命中游戏启动器、运行库 |
| `Qemu_Detection` / `antivm_vmware` | 含反虚拟机代码 | 命中驱动安装包 |

本项目做过两轮**实测审计**（语料 = Windows 系统二进制 + 本机真实安装的普通软件，共 4.3 GB），
共停用 **162 条规则 + 10 个整份文件**。审计方法与完整名单不随仓库分发
（其中含第三方规则正文），但方法可以直接复用：

1. 用**与产品同一份 libyara**（同一套编译宏与模块集）编译规则集；
2. 拿一批"已知干净"的二进制逐个扫描，统计**命中干净文件**的规则；
3. 命中即判为误报发生器 → 停用（整份文件全噪声就整份停用）。

评分侧已经做了分层防护（详见 [`../../docs/SCORING-POLICY.md`](../../docs/SCORING-POLICY.md)）：

| 证据 | 分值 | 结果 |
|---|---|---|
| 单条弱规则（能力型/库型目录） | 10 | 静默 |
| 单条普通规则 | 45 | **只提醒，不告警** |
| 2 条以上普通规则 | 90+ | 告警 |
| 单条高置信强签名 | 100 | 告警 |

即**单条规则再也无法独自弹窗**，但噪声通知仍会打扰用户 —— 所以审计不可省。

## 四、两条纪律

1. **不要把拉下来的第三方规则提交回本仓库** —— 那等于绕开上述全部许可考量。
2. 各上游的许可与免责声明请自行阅读并遵守；本项目不对第三方规则的内容与准确性负责。
