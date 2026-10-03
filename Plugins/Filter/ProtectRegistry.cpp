#include "DriverCommon.h"

static LARGE_INTEGER Cookie;

// P0-5(诊断): 置 1 时打印每次注册表回调的 NotifyClass, 用于确认本驱动枚举约定.
// 确认后可置 0(默认关), 避免刷日志.
// M1-1: 已改为符号枚举 REG_NOTIFY_CLASS (RegNtDeleteKey=0 / SetValueKey=1 /
// DeleteValueKey=2 / RenameKey=4), 与 wdm.h 定义一致, 不再依赖魔法数字.
static BOOLEAN RegOpDebug = FALSE;

// ============================================================================
// A/B 实验开关 (2026-10-03) —— BAM 注册表写入是否真的拒绝
//
// 背景: 实测 "cmd /c cmd /c echo X" 会让【子 cmd 从创建起就处于 Suspended,
//       且永远不会被恢复】(父 cmd 正常 WaitForSingleObject 死等 → 整链永久冻结)。
//       vcvars64.bat → VsDevCmd.bat 里的 `cmd /c vswhere.exe ...` 正是这个形状,
//       导致所有走 vcvars 的 VS 构建链卡死。cl.exe 本身只需 888ms, 不是编译器问题。
//
//       冻结时刻日志里唯一与进程创建相关的驱动动作就是本文件对
//       `*\Services\bam\*` 的 ACCESS_DENIED (BAM 由内核在进程创建路径上写入),
//       故用本开关做单变量 A/B。
//
// 1 = 保持原行为 (拒绝, 默认, 生产值)
// 0 = 只上报不拒绝 (实验值) —— 若置 0 后嵌套 cmd 不再冻结, 即定案
//
// ⚠ 实验结束后必须改回 1 并重编, 否则 BAM 拦截实际失效。
// ============================================================================
#ifndef ZETA_BAM_BLOCK_ENABLED
#define ZETA_BAM_BLOCK_ENABLED 1
#endif

static BOOLEAN IsBamRegistryPath(PCUNICODE_STRING KeyName) {
 if (!KeyName || !KeyName->Buffer) return FALSE;
 if (WildcardMatch(L"*\\Services\\bam\\*", KeyName->Buffer, KeyName->Length)) {
 return TRUE;
 }
 return FALSE;
}

static PWCHAR GetFullPath(PVOID RootObject, PUNICODE_STRING CompleteName, PULONG OutLength) {
 PWCHAR Buffer = NULL;
 ULONG TotalSize = 0;
 PCUNICODE_STRING RootName = NULL;
 BOOLEAN NeedFreeRootName = FALSE;

 if (RootObject) {
 NTSTATUS status = CmCallbackGetKeyObjectIDEx(&Cookie, RootObject, NULL, &RootName, 0);
 if (NT_SUCCESS(status) && RootName) {
 NeedFreeRootName = TRUE;
 }
 }

 ULONG RootLen = (RootName && RootName->Buffer) ? RootName->Length : 0;
 ULONG RelLen = (CompleteName && CompleteName->Buffer) ? CompleteName->Length : 0;

 TotalSize = RootLen + sizeof(WCHAR) + RelLen + sizeof(WCHAR);

 Buffer = (PWCHAR)ZetaAllocate(TotalSize);
 if (!Buffer) {
 if (NeedFreeRootName) CmCallbackReleaseKeyObjectIDEx(RootName);
 return NULL;
 }

 RtlZeroMemory(Buffer, TotalSize);

 PWCHAR Current = Buffer;
 if (RootLen > 0) {
 RtlCopyMemory(Current, RootName->Buffer, RootLen);
 Current += (RootLen / sizeof(WCHAR));
 if (Current > Buffer && *(Current - 1) != L'\\') {
 *Current = L'\\';
 Current++;
 }
 }

 if (RelLen > 0) {
 if (RootLen > 0 && CompleteName->Buffer[0] == L'\\') {
 RtlCopyMemory(Current, CompleteName->Buffer + 1, RelLen - sizeof(WCHAR));
 }
 else {
 RtlCopyMemory(Current, CompleteName->Buffer, RelLen);
 }
 }

 if (NeedFreeRootName) CmCallbackReleaseKeyObjectIDEx(RootName);

 if (OutLength) *OutLength = (ULONG)wcslen(Buffer) * sizeof(WCHAR);
 return Buffer;
}

static NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
 UNREFERENCED_PARAMETER(CallbackContext);

 // P0-自保护探针(2026-10-02): 必须在 IRQL / g_IsUnloading 提前 return 之前,
 // 且要在 NotifyClass switch 之前 —— 探针只用 ZwOpenKey, 会走 RegNtPreOpenKey,
 // 该类原本落到 default 放行, 所以计数必须放在最前才会被计入。
 if (g_RegProbeArmed) InterlockedIncrement(&g_RegProbeHits);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_SUCCESS;
 if (g_IsUnloading) return STATUS_SUCCESS;

 ULONG NotifyClass = (ULONG)(ULONG_PTR)Argument1;

 // P0-5(诊断): 临时打印实际 NotifyClass, 以确认本驱动的注册表回调枚举约定,
 // 避免在错误的 case 号上解析 Argument2 导致 0x135 蓝屏.
 if (RegOpDebug) {
     DbgPrint("ZETA_REG: NotifyClass=%lu Arg2=%p\n", NotifyClass, Argument2);
 }

 PWCHAR FullPath = NULL;
 UNICODE_STRING PathStr = { 0 };
 NTSTATUS result = STATUS_SUCCESS;

 // M1-1: 当前 case 用 wdm.h 的 REG_NOTIFY_CLASS 符号常量, 不再用魔法数字。
 // 真实枚举 (wdm.h): RegNtDeleteKey=0, RegNtSetValueKey=1,
 // RegNtDeleteValueKey=2, RegNtSetInformationKey=3, RegNtRenameKey=4。
 // Pre 变体为别名 (RegNtPreXxx == RegNtXxx), 由 CmRegisterCallbackEx 派发。
 UCHAR RegOp = IRP_OP_REG_SETVALUE;     // 默认写值; delete-value 复用该类型 + REG_SEM_VALUE_DELETE
 BOOLEAN IsKeyLevelOp = FALSE;          // delete-key / rename-key: 键级路径(无值名)
 BOOLEAN IsValueDelete = FALSE;         // delete-value: 置 REG_SEM_VALUE_DELETE 语义

 switch (NotifyClass) {
 case RegNtSetValueKey: {               // = 1
     PREG_SET_VALUE_KEY_INFORMATION SetInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
     if (!SetInfo || !SetInfo->Object) return STATUS_SUCCESS;
     FullPath = GetFullPath(SetInfo->Object, SetInfo->ValueName, NULL);
     RegOp = IRP_OP_REG_SETVALUE;
     break;
 }
 case RegNtDeleteValueKey: {            // = 2
     PREG_DELETE_VALUE_KEY_INFORMATION DelValInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
     if (!DelValInfo || !DelValInfo->Object) return STATUS_SUCCESS;
     FullPath = GetFullPath(DelValInfo->Object, DelValInfo->ValueName, NULL);
     RegOp = IRP_OP_REG_SETVALUE;       // 语义: 值被删 → 复用写值 op, 由 flag 区分
     IsValueDelete = TRUE;
     break;
 }
 case RegNtDeleteKey: {                 // = 0
     PREG_DELETE_KEY_INFORMATION DelKeyInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
     if (!DelKeyInfo || !DelKeyInfo->Object) return STATUS_SUCCESS;
     FullPath = GetFullPath(DelKeyInfo->Object, NULL, NULL);
     RegOp = IRP_OP_REG_DELETEKEY;
     IsKeyLevelOp = TRUE;
     break;
 }
 case RegNtRenameKey: {                 // = 4
     PREG_RENAME_KEY_INFORMATION RenInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
     if (!RenInfo || !RenInfo->Object) return STATUS_SUCCESS;
     FullPath = GetFullPath(RenInfo->Object, NULL, NULL); // 原键路径
     RegOp = IRP_OP_REG_RENAMEKEY;
     IsKeyLevelOp = TRUE;
     break;
 }
 // 注: RegNtSetInformationKey(3)/创建键(Ex) 等不在此处拦截。
 // 创建键原代码从未真正命中(case 1 实为 SetValueKey), 且拦截创建易引入新误报面,
 // 本任务(M1-1)只补 delete/rename 监控, 创建键由后续任务评估。
 default:
     return STATUS_SUCCESS;
 }

 if (!FullPath) return STATUS_SUCCESS;

 // M1-1: GetFullPath 对无值名(键级)路径会补尾部 '\'。精确规则如
 // "*\Image File Execution Options\sethc.exe" 不带尾斜杠, 故先去掉尾部 '\'。
 if (IsKeyLevelOp) {
     ULONG plen = (ULONG)wcslen(FullPath);
     if (plen > 1 && FullPath[plen - 1] == L'\\') FullPath[plen - 1] = L'\0';
 }

 RtlInitUnicodeString(&PathStr, FullPath);

 HANDLE Pid = PsGetCurrentProcessId();
 if (IsProcessTrusted(Pid)) {
 ZetaFree(FullPath);
 return STATUS_SUCCESS;
 }

 // Self-registration check: if a process writes a Run value with its own
 // filename (e.g. internat.exe writes Run\internat.exe), allow it.
 if (IsRunKeySelfRegistration(Pid, FullPath)) {
 DbgPrint("ZETA: Run key self-registration allowed: PID=%lu path=%ws\n", (ULONG)(ULONG_PTR)Pid, FullPath);
 ZetaFree(FullPath);
 return STATUS_SUCCESS;
 }

 // M1-1: 键级操作(delete/rename key) 路径不含值名, 规则多为 "...\Key\*" 形式,
 // 故对"整键"删除/改名等价于其下全部子项: 附加尾部 '\' 后做第二路规则匹配。
 WCHAR KeyProbe[MAX_PATH_LEN];
 PCWSTR RulePath = FullPath;
 UNICODE_STRING RulePathStr = PathStr;
 if (IsKeyLevelOp) {
     ULONG plen = (ULONG)wcslen(FullPath);
     if (plen > 0 && plen < MAX_PATH_LEN - 2) {
         RtlCopyMemory(KeyProbe, FullPath, plen * sizeof(WCHAR));
         KeyProbe[plen] = L'\\';
         KeyProbe[plen + 1] = L'\0';
         RulePath = KeyProbe;
         RtlInitUnicodeString(&RulePathStr, KeyProbe);
     }
 }

 if (CheckRegistryRule(&PathStr) || CheckRegistryRule(&RulePathStr)) {
 DbgPrint("ZETA: BLOCKED registry write by PID=%lu: %wZ\n", (ULONG)(ULONG_PTR)Pid, &PathStr);
 // 语义上下文：从注册表路径中提取敏感键特征
 ZETA_IRP_CONTEXT irpCtx;
 RtlZeroMemory(&irpCtx, sizeof(irpCtx));
 irpCtx.OperationType = RegOp;
 irpCtx.TrustLevel = TRUST_UNKNOWN;
 if (IsValueDelete) irpCtx.RegFlags |= REG_SEM_VALUE_DELETE;
 if (WildcardMatch(L"*\\CurrentVersion\\Run\\*", RulePath, (USHORT)wcslen(RulePath) * sizeof(WCHAR)) ||
     WildcardMatch(L"*\\CurrentVersion\\RunOnce\\*", RulePath, (USHORT)wcslen(RulePath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_RUN_KEY;
 if (WildcardMatch(L"*\\Services\\*", RulePath, (USHORT)wcslen(RulePath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_SERVICE_KEY;
 if (WildcardMatch(L"*\\Image File Execution Options\\*", RulePath, (USHORT)wcslen(RulePath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_IFEO_KEY;
 if (WildcardMatch(L"*\\Windows Defender\\*", RulePath, (USHORT)wcslen(RulePath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_DEFENDER_KEY;

 // Audit mode: record full registry details to ring buffer
 if (g_AuditMode >= AUDIT_MODE_ON) {
     ZETA_IRP_AUDIT_EXT auditExt;
     RtlZeroMemory(&auditExt, sizeof(auditExt));
     auditExt.Size = sizeof(ZETA_IRP_AUDIT_EXT);
     auditExt.IrpMajor = RegOp;
     // Extract value name from path (last component after \)
     USHORT pathLenW = (USHORT)wcslen(FullPath);
     PCWSTR lastSlash = FullPath;
     for (USHORT i = 0; i < pathLenW; i++) {
         if (FullPath[i] == L'\\') lastSlash = &FullPath[i + 1];
     }
     USHORT valLen = (USHORT)wcslen(lastSlash);
     if (valLen > 63) valLen = 63;
     RtlCopyMemory(auditExt.ValueName, lastSlash, valLen * sizeof(WCHAR));
     auditExt.ValueName[valLen] = L'\0';
     AuditRing_WriteEntry(3001, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length,
         &irpCtx, &auditExt);
 }

 SendMessageToUserWithContext(ZETA_MSG_REG_PROTECT, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length, &irpCtx);
 result = STATUS_ACCESS_DENIED;
 } else if (IsBamRegistryPath(&PathStr)) {
#if ZETA_BAM_BLOCK_ENABLED
 DbgPrint("ZETA: BLOCKED BAM registry access by PID=%lu: %wZ\n", (ULONG)(ULONG_PTR)Pid, &PathStr);
 SendMessageToUser(ZETA_MSG_REG_BAM, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length);
 result = STATUS_ACCESS_DENIED;
#else
 // A/B 实验值: 只上报不拒绝。上报内容带唯一标记, 使"当前加载的是哪一版驱动"
 // 在用户态日志里可验证 —— 否则两版日志完全一样, A/B 无法自证。
 DbgPrint("ZETA: [A/B] BAM access REPORTED ONLY (block disabled) PID=%lu: %wZ\n",
          (ULONG)(ULONG_PTR)Pid, &PathStr);
 {
     static const WCHAR abMarker[] =
         L"[A/B-VARIANT: BAM-BLOCK-DISABLED] (reported only, NTSTATUS unchanged)";
     SendMessageToUser(ZETA_MSG_REG_BAM, (ULONG)(ULONG_PTR)Pid,
                       (PWCHAR)abMarker, (ULONG)(wcslen(abMarker) * sizeof(WCHAR)));
 }
#endif
 }

 ZetaFree(FullPath);
 return result;
}

NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject) {
 static UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"320000.ZETA.Cm");
 NTSTATUS status = CmRegisterCallbackEx(RegistryCallback, &Altitude, DriverObject, NULL, &Cookie, NULL);

 if (!NT_SUCCESS(status)) {
  DbgPrint("ZETA: CmRegisterCallbackEx failed with status 0x%08lX, trying fallback altitude", status);
  static UNICODE_STRING FallbackAltitude = RTL_CONSTANT_STRING(L"320000.ZETA.Cm.Fallback");
  status = CmRegisterCallbackEx(RegistryCallback, &FallbackAltitude, DriverObject, NULL, &Cookie, NULL);
 }

 if (NT_SUCCESS(status)) {
  DbgPrint("ZETA: InitializeRegistryProtection succeeded");
 } else {
  DbgPrint("ZETA: InitializeRegistryProtection failed with final status 0x%08lX", status);
 }

 return status;
}

VOID UninitializeRegistryProtection() {
 if (Cookie.QuadPart != 0) {
 CmUnRegisterCallback(Cookie);
 Cookie.QuadPart = 0;
 }
}
