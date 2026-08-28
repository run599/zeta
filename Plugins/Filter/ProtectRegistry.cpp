#include "DriverCommon.h"

static LARGE_INTEGER Cookie;

// P0-5(诊断): 置 1 时打印每次注册表回调的 NotifyClass, 用于确认本驱动枚举约定.
// 确认后可置 0(默认关), 避免刷日志.
static BOOLEAN RegOpDebug = FALSE;

static BOOLEAN IsBamRegistryPath(PCUNICODE_STRING KeyName) {
 if (!KeyName || !KeyName->Buffer) return FALSE;
 if (WildcardMatch(L"*\\Services\\bam\\*", KeyName->Buffer, KeyName->Length)) {
 return TRUE;
 }
 return FALSE;
}

static BOOLEAN IsWriteAccess(ACCESS_MASK Access) {
 if (Access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
 DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) {
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

 switch (NotifyClass) {
 case 1: {
     PREG_CREATE_KEY_INFORMATION CreateInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
     if (!CreateInfo || !CreateInfo->CompleteName || !CreateInfo->CompleteName->Buffer) return STATUS_SUCCESS;
     if (!IsWriteAccess(CreateInfo->DesiredAccess)) return STATUS_SUCCESS;
     FullPath = GetFullPath(CreateInfo->RootObject, CreateInfo->CompleteName, NULL);
     break;
 }
 case 2: {
     PREG_SET_VALUE_KEY_INFORMATION SetInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
     if (!SetInfo || !SetInfo->Object) return STATUS_SUCCESS;
     FullPath = GetFullPath(SetInfo->Object, SetInfo->ValueName, NULL);
     break;
 }
 default:
     return STATUS_SUCCESS;
 }

 if (!FullPath) return STATUS_SUCCESS;

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

 if (CheckRegistryRule(&PathStr)) {
 DbgPrint("ZETA: BLOCKED registry write by PID=%lu: %wZ\n", (ULONG)(ULONG_PTR)Pid, &PathStr);
 // 语义上下文：从注册表路径中提取敏感键特征
 ZETA_IRP_CONTEXT irpCtx;
 RtlZeroMemory(&irpCtx, sizeof(irpCtx));
 irpCtx.OperationType = IRP_OP_REG_SETVALUE;
 irpCtx.TrustLevel = TRUST_UNKNOWN;
 if (WildcardMatch(L"*\\CurrentVersion\\Run\\*", FullPath, (USHORT)wcslen(FullPath) * sizeof(WCHAR)) ||
     WildcardMatch(L"*\\CurrentVersion\\RunOnce\\*", FullPath, (USHORT)wcslen(FullPath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_RUN_KEY;
 if (WildcardMatch(L"*\\Services\\*", FullPath, (USHORT)wcslen(FullPath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_SERVICE_KEY;
 if (WildcardMatch(L"*\\Image File Execution Options\\*", FullPath, (USHORT)wcslen(FullPath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_IFEO_KEY;
 if (WildcardMatch(L"*\\Windows Defender\\*", FullPath, (USHORT)wcslen(FullPath) * sizeof(WCHAR)))
     irpCtx.RegFlags |= REG_SEM_DEFENDER_KEY;

 // Audit mode: record full registry details to ring buffer
 if (g_AuditMode >= AUDIT_MODE_ON) {
     ZETA_IRP_AUDIT_EXT auditExt;
     RtlZeroMemory(&auditExt, sizeof(auditExt));
     auditExt.Size = sizeof(ZETA_IRP_AUDIT_EXT);
     auditExt.IrpMajor = 11; // IRP_OP_REG_SETVALUE
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

 SendMessageToUserWithContext(3001, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length, &irpCtx);
 result = STATUS_ACCESS_DENIED;
 } else if (IsBamRegistryPath(&PathStr)) {
 DbgPrint("ZETA: BLOCKED BAM registry access by PID=%lu: %wZ\n", (ULONG)(ULONG_PTR)Pid, &PathStr);
 SendMessageToUser(3002, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length);
 result = STATUS_ACCESS_DENIED;
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
