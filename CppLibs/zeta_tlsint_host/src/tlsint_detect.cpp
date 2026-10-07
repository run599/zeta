// zeta_tlsint 宿主侧规则判定（M2-3 中央判定 · MVP）
//
// 纯函数、无全局状态 —— 便于用合成样本单测（见 tests/tlsint_host_test.cpp 的 detect 模式）。
// 语义边界：这里是**内容级**判定，覆盖 DLP 外传与 C2 特征的最小可用集合；
// 与行为引擎评分的对接走 TlsIntAlertFn 回调（本模块只负责判定与上报，不负责处置）。
#include "tlsint_host.h"

#include <cstring>
#include <cstdio>
#include <cstdarg>

namespace {

const int SEV_INFO = 1, SEV_WARN = 2, SEV_HIGH = 3;

// 大小写不敏感子串查找（只对 ASCII 做折叠；二进制样本里非 ASCII 字节原样比较）
bool FindI(const unsigned char* d, ULONG n, const char* needle, ULONG* at)
{
    const size_t nl = ::strlen(needle);
    if (nl == 0 || n < nl) return false;
    for (ULONG i = 0; i + nl <= n; ++i) {
        size_t j = 0;
        for (; j < nl; ++j) {
            unsigned char a = d[i + j];
            unsigned char b = static_cast<unsigned char>(needle[j]);
            if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + 32);
            if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + 32);
            if (a != b) break;
        }
        if (j == nl) { if (at) *at = i; return true; }
    }
    return false;
}

bool StartsWithHttpMethod(const unsigned char* d, ULONG n)
{
    static const char* kMethods[] = { "GET ", "POST ", "PUT ", "HEAD ",
                                      "DELETE ", "OPTIONS ", "PATCH ", "CONNECT " };
    for (const char* m : kMethods) {
        const size_t l = ::strlen(m);
        if (n >= l && ::memcmp(d, m, l) == 0) return true;
    }
    return false;
}

// 银行卡号校验：Luhn。用它把"16~19 位纯数字"里约 90% 的随机噪声挡掉。
bool LuhnOk(const char* digits, int n)
{
    if (n <= 0) return false;
    int sum = 0, alt = 0;
    for (int i = n - 1; i >= 0; --i) {
        int v = digits[i] - '0';
        if (alt) { v *= 2; if (v > 9) v -= 9; }
        sum += v;
        alt = !alt;
    }
    return (sum % 10) == 0;
}

bool IsHexish(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

void Add(TlsIntFinding* out, int maxOut, int& cnt, int id, const wchar_t* name,
         int sev, const wchar_t* fmt, ...)
{
    if (cnt >= maxOut) return;
    TlsIntFinding& f = out[cnt];
    f.ruleId = id;
    f.ruleName = name;
    f.severity = sev;
    va_list ap;
    va_start(ap, fmt);
    ::_vsnwprintf_s(f.detail, _countof(f.detail), _TRUNCATE, fmt, ap);
    va_end(ap);
    ++cnt;
}

// 扫描连续数字串：识别身份证(18位 / 17位+X)与银行卡(16~19位 + Luhn)
void ScanDigitRuns(const unsigned char* d, ULONG n, TlsIntFinding* out, int maxOut, int& cnt)
{
    ULONG i = 0;
    while (i < n) {
        if (d[i] < '0' || d[i] > '9') { ++i; continue; }
        const ULONG start = i;
        char run[64];
        int r = 0;
        while (i < n && d[i] >= '0' && d[i] <= '9') {
            if (r < 63) run[r++] = static_cast<char>(d[i]);
            ++i;
        }
        const int totalDigits = static_cast<int>(i - start);
        if (totalDigits >= 64) continue;              // 超长数字串（哈希/时间戳）直接跳过
        // 前后是十六进制字母 → 多半是哈希/ID 片段，跳过以免误报
        const bool hexBefore = (start > 0) && IsHexish(d[start - 1]) &&
                               !(d[start - 1] >= '0' && d[start - 1] <= '9');
        if (hexBefore) continue;

        // 身份证：18 位，或 17 位 + X/x
        bool idLike = (r == 18);
        if (r == 17 && i < n && (d[i] == 'X' || d[i] == 'x')) idLike = true;
        if (idLike && run[0] >= '1' && run[0] <= '9') {
            Add(out, maxOut, cnt, 104, L"PII_CN_ID", SEV_HIGH,
                L"疑似身份证号（%d 位数字%s）", r,
                (r == 17) ? L"+X" : L"");
        }
        // 银行卡：16~19 位 + Luhn；首位限制为 2~6（主要 IIN），进一步压噪声
        if (r >= 16 && r <= 19 && run[0] >= '2' && run[0] <= '6' && LuhnOk(run, r)) {
            Add(out, maxOut, cnt, 105, L"PII_BANK_CARD", SEV_HIGH,
                L"疑似银行卡号（%d 位，Luhn 通过）", r);
        }
    }
}

// Host: 后面是不是纯字面 IP（无域名）—— 直连 IP 的 C2/beacon 特征
bool HostIsIpLiteral(const unsigned char* d, ULONG n)
{
    ULONG at = 0;
    if (!FindI(d, n, "host:", &at)) return false;
    ULONG p = at + 5;
    while (p < n && (d[p] == ' ' || d[p] == '\t')) ++p;
    if (p >= n) return false;
    int digits = 0, dots = 0;
    while (p < n && ((d[p] >= '0' && d[p] <= '9') || d[p] == '.' || d[p] == ':')) {
        if (d[p] >= '0' && d[p] <= '9') ++digits;
        else if (d[p] == '.') ++dots;
        else break;                                   // 端口起点（':'）即认为 IP 已定性
        ++p;
    }
    return dots >= 3 && digits >= 4;
}

} // namespace

int TlsIntDetect_Analyze(int dir, const unsigned char* data, unsigned long len,
                         TlsIntFinding* out, int maxOut)
{
    if (!data || len == 0 || !out || maxOut <= 0) return 0;
    if (len > 1024UL * 1024UL) len = 1024UL * 1024UL;   // 防御性上限
    const bool outbound = (dir != 0);
    int cnt = 0;

    // ── R101 私钥外泄 ──
    if (FindI(data, len, "-----BEGIN", nullptr) && FindI(data, len, "PRIVATE KEY", nullptr)) {
        Add(out, maxOut, cnt, 101, L"SECRET_PRIVATE_KEY", SEV_HIGH,
            L"外发明文含私钥头（BEGIN ... PRIVATE KEY）");
    }
    // ── R102 凭据头 ──
    ULONG at = 0;
    if (FindI(data, len, "authorization: basic ", &at) ||
        FindI(data, len, "authorization: bearer ", &at)) {
        Add(out, maxOut, cnt, 102, L"CRED_AUTH_HEADER", SEV_HIGH,
            L"外发明文含 Authorization 凭据头（偏移 %lu）", (unsigned long)at);
    }
    // ── R103 表单口令字段（仅外发，限制噪声）──
    if (outbound && (FindI(data, len, "password=", nullptr) ||
                     FindI(data, len, "passwd=", nullptr) ||
                     FindI(data, len, "pwd=", nullptr))) {
        Add(out, maxOut, cnt, 103, L"CRED_PASSWORD_FIELD", SEV_WARN,
            L"外发明文含口令字段（password=/passwd=/pwd=）");
    }
    // ── R106 云凭证/令牌 ──
    if (FindI(data, len, "AKIA", &at) && at + 20 <= len) {
        int alnum = 0;
        for (ULONG k = at + 4; k < len && k < at + 20; ++k) {
            unsigned char c = data[k];
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ++alnum; else break;
        }
        if (alnum >= 16) Add(out, maxOut, cnt, 106, L"CLOUD_KEY", SEV_HIGH, L"疑似 AWS AccessKeyId（AKIA+16）");
    }
    if (FindI(data, len, "ghp_", nullptr))
        Add(out, maxOut, cnt, 106, L"CLOUD_KEY", SEV_HIGH, L"疑似 GitHub PAT（ghp_）");
    if (FindI(data, len, "xoxb-", nullptr))
        Add(out, maxOut, cnt, 106, L"CLOUD_KEY", SEV_HIGH, L"疑似 Slack token（xoxb-）");
    if (FindI(data, len, "AIza", nullptr))
        Add(out, maxOut, cnt, 106, L"CLOUD_KEY", SEV_HIGH, L"疑似 Google API key（AIza）");

    // ── R104/R105 PII ──
    ScanDigitRuns(data, len, out, maxOut, cnt);

    if (outbound) {
        // ── R201 大样本外传 ──
        if (len >= 32768 && StartsWithHttpMethod(data, len)) {
            Add(out, maxOut, cnt, 201, L"EXFIL_LARGE_BODY", SEV_WARN,
                L"单条外发明文 %lu 字节（≥32KB，HTTP 请求体）", (unsigned long)len);
        }
        // ── R204 上传方法 + 非小体量 ──
        else if (len >= 4096 && (len >= 4) &&
                 (::memcmp(data, "POST", 4) == 0 || ::memcmp(data, "PUT", 3) == 0)) {
            Add(out, maxOut, cnt, 204, L"EXFIL_UPLOAD_METHOD", SEV_WARN,
                L"外发 %lu 字节的上传请求（POST/PUT）", (unsigned long)len);
        }
        // ── R202 直连字面 IP ──
        if (HostIsIpLiteral(data, len)) {
            Add(out, maxOut, cnt, 202, L"C2_IP_LITERAL_HOST", SEV_WARN,
                L"Host 头为字面 IP（无域名）—— beacon/C2 常见特征");
        }
        // ── R203 工具化客户端 ──
        if ((FindI(data, len, "user-agent: curl", nullptr)) ||
            (FindI(data, len, "user-agent: wget", nullptr)) ||
            (FindI(data, len, "python-requests", nullptr)) ||
            (FindI(data, len, "user-agent: powershell", nullptr)) ||
            (FindI(data, len, "go-http-client", nullptr))) {
            Add(out, maxOut, cnt, 203, L"SUSPICIOUS_UA", SEV_INFO,
                L"外发使用命令行/脚本类 User-Agent（非浏览器）");
        }
    }
    return cnt;
}
