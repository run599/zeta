#include "DriverCommon.h"

static LARGE_INTEGER Cookie;

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

 if (CheckRegistryRule(&PathStr)) {
 DbgPrint("ZETA: BLOCKED registry write by PID=%lu: %wZ\n", (ULONG)(ULONG_PTR)Pid, &PathStr);
 SendMessageToUser(3001, (ULONG)(ULONG_PTR)Pid, PathStr.Buffer, PathStr.Length);
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
