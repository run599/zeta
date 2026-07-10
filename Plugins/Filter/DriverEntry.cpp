#include "DriverCommon.h"

DRIVER_DATA GlobalData;
static BOOLEAN g_ImageNotifyRegistered = FALSE;
WORK_ITEM_TRACKER g_WorkItemTracker = { 0 };

// Trust window global variables
LIST_ENTRY g_TrustWindowList;
KSPIN_LOCK g_TrustWindowLock;

// Driver log level (default: INFO, can be changed via ZETA_CMD_SET_LOG_LEVEL)
ULONG g_DriverLogLevel = ZETA_LOG_INFO;

// DriverEntry initialization state (tracked for log summary on connect)
// Also includes rule counts set by ProtectRules.cpp during LoadRulesFromDisk
static LARGE_INTEGER g_DriverStartTick = {0};
DRIVER_STATE g_DriverState = {0};

static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
 UNREFERENCED_PARAMETER(VolumeDeviceType);
 UNREFERENCED_PARAMETER(VolumeFilesystemType);
 return STATUS_SUCCESS;
}

static NTSTATUS InstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
 return STATUS_SUCCESS;
}

static VOID InstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
}

static VOID InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
}

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
 UNREFERENCED_PARAMETER(Flags);

 DbgPrint("ZETA: DriverUnload: begin\n");

 // 1. Set unload flag
 g_IsUnloading = TRUE;

 // 2. Wait for any pending deferred work items to complete
 // This prevents use-after-free if work items are still accessing g_PendingOps
 if (InterlockedCompareExchange(&g_WorkItemTracker.PendingCount, 0, 0) > 0) {
  LARGE_INTEGER timeout;
  timeout.QuadPart = -50000000LL; // 5 seconds
  KeWaitForSingleObject(&g_WorkItemTracker.CompletionEvent, Executive, KernelMode, FALSE, &timeout);
  KeResetEvent(&g_WorkItemTracker.CompletionEvent);
  DbgPrint("ZETA: DriverUnload: pending work items drained\n");
 }

 // 3. Remove process creation notify for LineageTracker
 if (g_LineageTrackerEnabled) {
  PsSetCreateProcessNotifyRoutine(LineageTracker_OnProcessCreate, TRUE);
  g_LineageTrackerEnabled = FALSE;
  DbgPrint("ZETA: DriverUnload: process notify removed\n");
 }

 // 4. Remove image load notify
 if (g_ImageNotifyRegistered) {
  PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
  g_ImageNotifyRegistered = FALSE;
  DbgPrint("ZETA: DriverUnload: image notify removed\n");
 }

 // 5. Unregister CmCallback (registry protection)
 UninitializeRegistryProtection();
 DbgPrint("ZETA: DriverUnload: registry protection uninitialized\n");

 // 6. Close communication port (prevents new user-mode commands)
 if (GlobalData.ServerPort) {
  FltCloseCommunicationPort(GlobalData.ServerPort);
  GlobalData.ServerPort = NULL;
  DbgPrint("ZETA: DriverUnload: communication port closed\n");
 }

 // 7. Stop timeout checker thread and cleanup pending operations + trust window
 // MUST happen BEFORE filter unregistration to prevent thread accessing freed memory
 StopTimeoutChecker();
 CleanupAllPendingOperations();
 CleanupTrustWindow();
 DbgPrint("ZETA: DriverUnload: timeout checker stopped, pending ops and trust window cleaned up\n");
 
 // 8. Unregister filter (waits for minifilter callbacks to drain)
 if (GlobalData.FilterHandle) {
  FltUnregisterFilter(GlobalData.FilterHandle);
  GlobalData.FilterHandle = NULL;
  DbgPrint("ZETA: DriverUnload: filter unregistered\n");
 }

 // 9. Cleanup rules and engine (MUST happen AFTER filter unregistration)
 UnloadRules();
 UninitializeRulesEngine();
 DbgPrint("ZETA: DriverUnload: rules and engine cleaned up\n");

 DbgPrint("ZETA: DriverUnload: complete\n");
 return STATUS_SUCCESS;
}

static NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) {
 UNREFERENCED_PARAMETER(PortCookie);

 if (!InputBuffer || InputBufferLength < sizeof(ZETA_USER_MESSAGE)) {
 return STATUS_INVALID_PARAMETER;
 }

 PZETA_USER_MESSAGE msg = (PZETA_USER_MESSAGE)InputBuffer;

 // Handle init log request: build the DriverInit summary string in OutputBuffer
 if (msg->Command == ZETA_CMD_GET_INITLOG) {
  WCHAR LogBuf[2048];
  ULONG LogLen;
  RtlStringCbPrintfW(LogBuf, sizeof(LogBuf),
   L"DriverInit: RulesEngine=%ls Filter=%ls Port=%ls ProcessProt=%ls(0x%08lX) RegProt=%ls ImageNotify=%ls FilterStart=%ls AnyFail=%ls\n"
   L"Kernel Rules: Rules_Driver_P1=%ls(0x%08lX) Rules_User=%ls(0x%08lX)\n"
   L"Rules: RegistryBlock=%lu RegistryTrust=%lu ProcessTrust=%lu ProcessExploit=%lu FileProtect=%lu FileExcept=%lu FileSafe=%lu FileRansom=%lu",
   g_DriverState.RulesEngineOK ? L"OK" : L"FAIL",
   g_DriverState.FilterRegistered ? L"OK" : L"FAIL",
   g_DriverState.PortCreated ? L"OK" : L"FAIL",
   g_DriverState.ProcessProtectionOK ? L"OK" : L"FAIL",
   g_DriverState.ProcessProtectionStatus,
   g_DriverState.RegistryProtectionOK ? L"OK" : L"FAIL",
   g_DriverState.ImageNotifyOK ? L"OK" : L"FAIL",
   g_DriverState.FilterStarted ? L"OK" : L"FAIL",
   g_DriverState.AnyFailure ? L"YES" : L"NO",
   NT_SUCCESS(g_DriverState.SystemRulesStatus) ? L"OK" : L"FAIL",
   g_DriverState.SystemRulesStatus,
   NT_SUCCESS(g_DriverState.UserRulesStatus) ? L"OK" : L"FAIL",
   g_DriverState.UserRulesStatus,
   g_DriverState.RegistryBlockCount,
   g_DriverState.RegistryTrustedCount,
   g_DriverState.ProcessTrustedCount,
   g_DriverState.ProcessExploitCount,
   g_DriverState.FileProtectedCount,
   g_DriverState.FileExceptionCount,
   g_DriverState.FileSafeExceptionCount,
   g_DriverState.FileRansomCount
  );

  LogLen = (ULONG)((wcslen(LogBuf) + 1) * sizeof(WCHAR));
  if (OutputBuffer && OutputBufferLength >= LogLen) {
   RtlCopyMemory(OutputBuffer, LogBuf, LogLen);
   if (ReturnOutputBufferLength) *ReturnOutputBufferLength = LogLen;
  } else if (ReturnOutputBufferLength) {
   *ReturnOutputBufferLength = 0;
  }
  return STATUS_SUCCESS;
 }

 // Handle allow/deny pending operation commands - use deferred work item for IRQL safety
if (msg->Command == ZETA_CMD_ALLOW_OP || msg->Command == ZETA_CMD_DENY_OP) {
 ULONG targetPid = 0;
 for (int i = 0; i < MAX_PATH_LEN && msg->Path[i]; i++) {
 targetPid = targetPid * 10 + (ULONG)(msg->Path[i] - L'0');
 }
 if (targetPid > 0) {
 // Queue deferred work item to complete at PASSIVE_LEVEL
 QueueCompletePendingOperation(targetPid, msg->Command == ZETA_CMD_ALLOW_OP);
 ZETA_INFO("Queued %s operation for PID=%lu\n",
 msg->Command == ZETA_CMD_ALLOW_OP ? "ALLOW" : "DENY", targetPid);
 }
 if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
 return STATUS_SUCCESS;
}

 // Handle experimental feature toggle commands
 if (msg->Command == ZETA_CMD_SET_LINEAGE_TRACKER) {
  // Path[0] = L'1' means enable, anything else means disable
  BOOLEAN enable = (msg->Path[0] == L'1');
  LineageTracker_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_RANSOM_EXPERIMENTAL) {
  BOOLEAN enable = (msg->Path[0] == L'1');
  RansomExp_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_LEARNING_MODE) {
  BOOLEAN enable = (msg->Path[0] == L'1');
  LearningMode_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_RELOAD_RULES) {
    // Reload all rules from disk (reads JSON files again)
    UnloadRules();
    NTSTATUS reloadStatus = LoadRulesFromDisk(NULL);
    if (NT_SUCCESS(reloadStatus)) {
        ZETA_INFO("Rules reloaded successfully via CMD_RELOAD_RULES\n");
    } else {
        ZETA_ERROR("Rules reload FAILED via CMD_RELOAD_RULES (0x%08X)\n", reloadStatus);
    }
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command != ZETA_CMD_ADD_WHITELIST && msg->Command != ZETA_CMD_REMOVE_WHITELIST) {
 return STATUS_INVALID_PARAMETER;
 }

 ULONG pathLenBytes = 0;
 ULONG maxPathOffset = InputBufferLength - sizeof(ULONG);
 ULONG maxPathChars = maxPathOffset / sizeof(WCHAR);
 
 for (ULONG i = 0; i < maxPathChars && i < MAX_PATH_LEN; i++) {
 if (msg->Path[i] == L'\0') {
 pathLenBytes = i * sizeof(WCHAR);
 break;
 }
 }
 
 if (pathLenBytes == 0) {
 return STATUS_INVALID_PARAMETER;
 }

 UNICODE_STRING us;
 us.Buffer = msg->Path;
 us.Length = (USHORT)pathLenBytes;
 us.MaximumLength = (USHORT)min(maxPathOffset, MAX_PATH_LEN * sizeof(WCHAR));

 if (msg->Command == ZETA_CMD_ADD_WHITELIST) {
 AddDynamicWhitelist(&us);
 } else {
 RemoveDynamicWhitelist(&us);
 }

 if (ReturnOutputBufferLength) {
 *ReturnOutputBufferLength = 0;
 }
 return STATUS_SUCCESS;
}

static NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie) {
 UNREFERENCED_PARAMETER(ServerPortCookie);
 UNREFERENCED_PARAMETER(ConnectionContext);
 UNREFERENCED_PARAMETER(SizeOfContext);
 UNREFERENCED_PARAMETER(ConnectionPortCookie);

 PEPROCESS callingProcess = PsGetCurrentProcess();
 PUNICODE_STRING imageName = NULL;
 NTSTATUS status = SeLocateProcessImageName(callingProcess, &imageName);
 
 if (!NT_SUCCESS(status) || !imageName || !imageName->Buffer) {
 ZETA_ERROR("PortConnect FAILED - cannot get caller image name (0x%08X)\n", status);
 if (imageName) ExFreePool(imageName);
 return STATUS_ACCESS_DENIED;
 }

 BOOLEAN isAllowed = WildcardMatch(L"*\\ZETA.exe", imageName->Buffer, imageName->Length);
 ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

 if (!isAllowed) {
 ZETA_WARN("PortConnect BLOCKED - caller is not ZETA.exe (PID=%lu, Image=%wZ)\n", callerPid, imageName);
 ExFreePool(imageName);
 return STATUS_ACCESS_DENIED;
 }

 ExFreePool(imageName);

 KIRQL OldIrql;
 KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

 GlobalData.ClientPort = ClientPort;
 GlobalData.ZetaPid = callerPid;
 ObReferenceObject(callingProcess);
 GlobalData.UserProcess = callingProcess;

 ExReInitializeRundownProtection(&GlobalData.PortRundown);

 KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

 ZETA_INFO("PortConnect SUCCESS - ZETA.exe connected (PID=%lu)\n", callerPid);

 // NOTE: Init log will be sent when ZETA.exe sends ZETA_CMD_GET_INITLOG via PortMessage.
 // Can't use FltSendMessage during PortConnect (deadlock), and no system thread needed.

 return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie) {
 UNREFERENCED_PARAMETER(ConnectionCookie);

 ULONG oldPid = GlobalData.ZetaPid;
 ZETA_INFO("PortDisconnect - ZETA.exe disconnected (PID=%lu)\n", oldPid);
 DriverLog(oldPid, L"PortDisconnect: ZETA.exe disconnected (PID=%lu)", oldPid);

 KIRQL OldIrql;
 KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

 PEPROCESS oldProcess = GlobalData.UserProcess;
 GlobalData.ClientPort = NULL;
 GlobalData.ZetaPid = 0;
 GlobalData.UserProcess = NULL;

 KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

 ExWaitForRundownProtectionRelease(&GlobalData.PortRundown);
 
 if (oldProcess) {
 ObDereferenceObject(oldProcess);
 }
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
 { IRP_MJ_CREATE, 0, ProtectFile_PreCreate, NULL },
 { IRP_MJ_WRITE, 0, ProtectFile_PreWrite, NULL },
 { IRP_MJ_SET_INFORMATION, 0, ProtectFile_PreSetInfo, NULL },
 { IRP_MJ_SET_SECURITY, 0, ProtectFile_SetSecurity, NULL },
 { IRP_MJ_FILE_SYSTEM_CONTROL, 0, ProtectFile_FileSystemControl, NULL },
 { IRP_MJ_DEVICE_CONTROL, 0, ProtectBoot_PreDeviceControl, NULL },
 { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
 sizeof(FLT_REGISTRATION),
 FLT_REGISTRATION_VERSION,
 0,
 NULL,
 Callbacks,
 DriverUnload,
 InstanceSetup,
 InstanceQueryTeardown,
 InstanceTeardownStart,
 InstanceTeardownComplete,
 NULL,
 NULL,
 NULL
};

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
 NTSTATUS status = STATUS_SUCCESS;
 PSECURITY_DESCRIPTOR sd = NULL;
 OBJECT_ATTRIBUTES oa = { 0 };
 UNICODE_STRING name = { 0 };

 ZETA_DEBUG("DriverEntry begin\n");

 RtlZeroMemory(&GlobalData, sizeof(GlobalData));
 GlobalData.DriverObject = DriverObject;
 KeInitializeSpinLock(&GlobalData.PortMutex);
 KeInitializeSpinLock(&GlobalData.TrackerMutex);
 KeInitializeSpinLock(&g_SilverFoxLock);
 RtlZeroMemory(&g_SilverFoxTrackers, sizeof(g_SilverFoxTrackers));
 ZETA_DEBUG("Global data initialized\n");

 ExInitializeRundownProtection(&GlobalData.PortRundown);
 ZETA_DEBUG("Rundown protection initialized\n");

 KeInitializeEvent(&g_WorkItemTracker.CompletionEvent, SynchronizationEvent, FALSE);
 ZETA_DEBUG("WorkItemTracker event initialized\n");

 KeQuerySystemTime(&g_DriverStartTick);

	InitializeRulesEngine();
	g_DriverState.RulesEngineOK = TRUE;
	ZETA_DEBUG("Rules engine initialized\n");

	// [STEP8] Initialize pending operations queue, timeout checker, and trust window
	InitializePendingOps();
	InitializeTrustWindow();
	StartTimeoutChecker();
	ZETA_DEBUG("PendingOps, TrustWindow and TimeoutChecker initialized\n");

	ZETA_DEBUG("Registering filter...\n");
 status = FltRegisterFilter(DriverObject, &FilterRegistration, &GlobalData.FilterHandle);
 if (!NT_SUCCESS(status)) {
 ZETA_ERROR("FltRegisterFilter FAILED (0x%08X)\n", status);
 return status;
 }
 g_DriverState.FilterRegistered = TRUE;
 ZETA_INFO("Filter registered (Handle=0x%p)\n", GlobalData.FilterHandle);

 ZETA_DEBUG("Creating communication port...\n");
 status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
 if (NT_SUCCESS(status)) {
 RtlInitUnicodeString(&name, ZETA_PORT_NAME);
 InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
 status = FltCreateCommunicationPort(GlobalData.FilterHandle, &GlobalData.ServerPort, &oa, NULL, PortConnect, PortDisconnect, PortMessage, 5);
 FltFreeSecurityDescriptor(sd);
 }

 if (!NT_SUCCESS(status)) {
 ZETA_ERROR("Communication port creation FAILED (0x%08X)\n", status);
 FltUnregisterFilter(GlobalData.FilterHandle);
 GlobalData.FilterHandle = NULL;
 return status;
 }
 g_DriverState.PortCreated = TRUE;
 DbgPrint("ZETA: Communication port created (Port=0x%p)\n", GlobalData.ServerPort);

 DbgPrint("ZETA: Starting filter...\n");
 status = FltStartFiltering(GlobalData.FilterHandle);
 if (!NT_SUCCESS(status)) {
 g_DriverState.AnyFailure = TRUE;
 DbgPrint("ZETA: FltStartFiltering FAILED (0x%08X) - cleaning up\n", status);

 if (GlobalData.FilterHandle) {
 FltUnregisterFilter(GlobalData.FilterHandle);
 GlobalData.FilterHandle = NULL;
 }

 return status;
 }
 g_DriverState.FilterStarted = TRUE;

 status = LoadRulesFromDisk(RegistryPath);
	g_DriverState.RulesLoaded = NT_SUCCESS(status);
	if (!NT_SUCCESS(status)) {
	g_DriverState.AnyFailure = TRUE;
	ZETA_ERROR("LoadRulesFromDisk FAILED (0x%08X) - continuing without rules\n", status);
	} else {
	ZETA_INFO("Rules loaded successfully\n");
	}

	// Initialize learning whitelist
	LearningWhitelist_Init();
	ZETA_DEBUG("LearningWhitelist initialized\n");

	// Enable experimental features
	RansomExp_SetEnabled(TRUE);
	LearningMode_SetEnabled(FALSE);
	ZETA_DEBUG("Experimental features initialized\n");

	// [STEP3] Process creation notify for LineageTracker
	g_LineageTrackerEnabled = TRUE;
	g_DriverState.LineageTrackerOK = FALSE;
	status = PsSetCreateProcessNotifyRoutine(LineageTracker_OnProcessCreate, FALSE);
	if (!NT_SUCCESS(status)) {
	ZETA_ERROR("PsSetCreateProcessNotifyRoutine FAILED (0x%08X) - LineageTracker unavailable\n", status);
	g_DriverState.AnyFailure = TRUE;
	g_LineageTrackerEnabled = FALSE;
	} else {
	g_DriverState.LineageTrackerOK = TRUE;
	ZETA_INFO("Process creation notify registered for LineageTracker\n");
	}

	// [STEP4] Image load notify
	g_ImageNotifyRegistered = FALSE;
	g_DriverState.ImageNotifyOK = FALSE;
	status = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
	if (!NT_SUCCESS(status)) {
	ZETA_ERROR("PsSetLoadImageNotifyRoutine FAILED (0x%08X)\n", status);
	g_DriverState.AnyFailure = TRUE;
	} else {
	g_ImageNotifyRegistered = TRUE;
	g_DriverState.ImageNotifyOK = TRUE;
	ZETA_INFO("Image load notify registered\n");
	}

	// [STEP5] Process protection via ObRegisterCallbacks (DISABLED - crashes during load)
	g_DriverState.ProcessProtectionOK = FALSE;
	g_DriverState.ProcessProtectionStatus = STATUS_NOT_SUPPORTED;
	ZETA_INFO("Process protection SKIPPED - requires further investigation\n");

	// [STEP6] Registry protection via CmRegisterCallbackEx
	g_DriverState.RegistryProtectionOK = FALSE;
	status = InitializeRegistryProtection(DriverObject);
	if (!NT_SUCCESS(status)) {
	g_DriverState.AnyFailure = TRUE;
	ZETA_ERROR("InitializeRegistryProtection FAILED (0x%08X)\n", status);
	} else {
	g_DriverState.RegistryProtectionOK = TRUE;
	ZETA_INFO("Registry protection initialized successfully\n");
	}

	DbgPrint("ZETA: DriverEntry SUCCESS - filter is now active\n");
 return status;
}

