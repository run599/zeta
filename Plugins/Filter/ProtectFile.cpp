#include "DriverCommon.h"

// ============================================================================
// Silver Fox detector: tracks PE file release patterns per process
// Silver Fox trait: releases to both "normal" (signed) and "suspicious" (unsigned) locations
// ============================================================================

SILVERFOX_TRACKER g_SilverFoxTrackers[64] = {0};
KSPIN_LOCK g_SilverFoxLock = {0};



static BOOLEAN IsSignedLocation(PUNICODE_STRING Path) {
 if (!Path || !Path->Buffer) return FALSE;

 // Windows system directories
 if (WildcardMatch(L"*\\Windows\\System32\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\SysWOW64\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\WinSxS\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\Microsoft.NET\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\*", Path->Buffer, Path->Length)) return TRUE;

 // Program Files / Common Files
 if (WildcardMatch(L"*\\Program Files\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Program Files (x86)\\*", Path->Buffer, Path->Length)) return TRUE;
 if (WildcardMatch(L"*\\Common Files\\*", Path->Buffer, Path->Length)) return TRUE;

 // ProgramData
 if (WildcardMatch(L"*\\ProgramData\\*", Path->Buffer, Path->Length)) return TRUE;

 // User-installed tools (Electron apps, IDEs, package managers)
 if (WildcardMatch(L"*\\AppData\\Local\\Programs\\*", Path->Buffer, Path->Length)) return TRUE;

 return FALSE;
}

static BOOLEAN IsPEExtension(PUNICODE_STRING Path) {
 if (!Path || !Path->Buffer) return FALSE;

 SIZE_T len = Path->Length / sizeof(WCHAR);
 if (len < 4) return FALSE;

 WCHAR* buf = Path->Buffer;
 WCHAR c1 = (WCHAR)((buf[len-3] | 0x20)), c2 = (WCHAR)((buf[len-2] | 0x20)),
 c3 = (WCHAR)((buf[len-1] | 0x20)), c4 = buf[len-4];

 // .exe, .dll, .sys, .ocx, .scr
 if (c4 == L'.') {
 if ((c1==L'e' && c2==L'x' && c3==L'e')) return TRUE;
 if ((c1==L'd' && c2==L'l' && c3==L'l')) return TRUE;
 if ((c1==L's' && c2==L'y' && c3==L's')) return TRUE;
 if ((c1==L'o' && c2==L'c' && c3==L'x')) return TRUE;
 if ((c1==L's' && c2==L'c' && c3==L'r')) return TRUE;
 }
 return FALSE;
}

static BOOLEAN IsArchiveExtension(PUNICODE_STRING Path) {
    if (!Path || !Path->Buffer) return FALSE;
    SIZE_T len = Path->Length / sizeof(WCHAR);
    if (len < 4) return FALSE;
    WCHAR* buf = Path->Buffer;
    WCHAR c1 = (WCHAR)(buf[len-3] | 0x20), c2 = (WCHAR)(buf[len-2] | 0x20),
         c3 = (WCHAR)(buf[len-1] | 0x20), c4 = buf[len-4];
    if (c4 != L'.') return FALSE;
    // .zip .7z .rar .tar .iso .cab
    if ((c1==L'z' && c2==L'i' && c3==L'p')) return TRUE;
    if ((c1==L'7'  && c2==L'z'                 )) return TRUE;
    if ((c1==L'r' && c2==L'a' && c3==L'r')) return TRUE;
    if ((c1==L't' && c2==L'a' && c3==L'r')) return TRUE;
    if ((c1==L'i' && c2==L's' && c3==L'o')) return TRUE;
    if ((c1==L'c' && c2==L'a' && c3==L'b')) return TRUE;
    return FALSE;
}

// Returns TRUE if SilverFox pattern detected (caller should pend operation)
// WARNING: This function accesses paged memory via PsLookupProcessByProcessId.
// Caller MUST ensure PASSIVE_LEVEL before invoking.
static BOOLEAN CheckSilverFoxPattern(ULONG Pid, PUNICODE_STRING FileName) {
    if (!IsPEExtension(FileName)) return FALSE;

    // Skip archives - they can't execute code, no security value in tracking
    if (IsArchiveExtension(FileName)) return FALSE;

    // Skip system-trusted paths (System32, Program Files, etc.)
    if (IsSignedLocation(FileName)) return FALSE;

    // Non-learning: check whitelist before expensive tracking
    // Cached per PID to avoid expensive PsLookupProcessByProcessId on every call
    {
        static ULONG s_CachedPid = 0;
        static BOOLEAN s_CachedResult = FALSE;
        if ((ULONG)(ULONG_PTR)Pid == s_CachedPid) {
            if (s_CachedResult) return FALSE;
        } else {
            BOOLEAN allowed = LearningWhitelist_IsProcessAllowed((HANDLE)(ULONG_PTR)Pid);
            s_CachedPid = (ULONG)(ULONG_PTR)Pid;
            s_CachedResult = allowed;
            if (allowed) return FALSE;
        }
    }

    KIRQL oldIrql;
    PSILVERFOX_TRACKER tracker = NULL;

    KeAcquireSpinLock(&g_SilverFoxLock, &oldIrql);

    for (int i = 0; i < 64; i++) {
        LONG pid = g_SilverFoxTrackers[i].ProcessId;
        if (pid == 0) {
            LONG prev = InterlockedCompareExchange((volatile LONG*)&g_SilverFoxTrackers[i].ProcessId, Pid, 0);
            if (prev == 0) {
                tracker = &g_SilverFoxTrackers[i];
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                tracker->StartTime.QuadPart = now.QuadPart;
                DbgPrint("ZETA: SilverFox new tracker[%d] for PID=%lu\n", i, Pid);
                break;
            }
        }
        if ((ULONG)pid == Pid) {
            tracker = &g_SilverFoxTrackers[i];
            break;
        }
    }

    if (!tracker) {
        KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
        DbgPrint("ZETA: SilverFox no tracker slot for PID=%lu\n", Pid);
        return FALSE;
    }

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    if ((now.QuadPart - tracker->StartTime.QuadPart) > 10000000) {
        DbgPrint("ZETA: SilverFox timeout reset for PID=%lu (%d releases)\n", Pid, tracker->EntryCount);
        InterlockedExchange(&tracker->EntryCount, 0);
        InterlockedExchange(&tracker->Alerted, 0);
        tracker->StartTime.QuadPart = now.QuadPart;
    }

    LONG prevCount = tracker->EntryCount;
    if (prevCount >= SILVERFOX_MAX_RELEASES) {
        if (!tracker->Alerted) {
            tracker->Alerted = 1;
            KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
            DbgPrint("ZETA: SilverFox ALERT - PID=%lu exceeded max releases (%d)\n", Pid, SILVERFOX_MAX_RELEASES);
            WCHAR msgBuf[] = L"SilverFox: too many PE releases";
            SendMessageToUser(ZETA_MSG_SILVERFOX_DETECTED, Pid, msgBuf, (USHORT)(sizeof(msgBuf) - sizeof(WCHAR)));
        } else {
            KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
        }
        return FALSE;
    }

    LONG newCount = InterlockedIncrement(&tracker->EntryCount);
    DbgPrint("ZETA: SilverFox PID=%lu release %d/%d: %wZ\n", Pid, newCount, SILVERFOX_MAX_RELEASES, FileName);
    if (newCount <= SILVERFOX_MAX_RELEASES) {
        LONG idx = newCount - 1;
        if (idx >= 0 && idx < SILVERFOX_MAX_RELEASES) {
            SIZE_T copyLen = FileName->Length;
            if (copyLen >= MAX_PATH_LEN * sizeof(WCHAR)) copyLen = (MAX_PATH_LEN - 1) * sizeof(WCHAR);
            RtlCopyMemory(tracker->Entries[idx].Path, FileName->Buffer, copyLen);
            tracker->Entries[idx].Path[copyLen / sizeof(WCHAR)] = L'\0';
        }
    }

    if (tracker->Alerted) {
        KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
        return FALSE;
    }

    LONG totalCount = tracker->EntryCount;
    if (totalCount < 3) {
        KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
        return FALSE;
    }

    // Build path list for user-mode signature verification
    // Format: "COUNT|PATH1\0PATH2\0PATH3\0..."
    WCHAR msgBuf[MAX_PATH_LEN];
    LONG written = 0;

    // Pack count + all paths (null-separated)
    for (LONG i = 0; i < totalCount && i < SILVERFOX_MAX_RELEASES; i++) {
        WCHAR* src = tracker->Entries[i].Path;
        WCHAR* dst = msgBuf + written;
        while (*src && written < MAX_PATH_LEN - 1) {
            *dst++ = *src++;
            written++;
        }
        if (written < MAX_PATH_LEN - 1) {
            *dst++ = L'|';
            written++;
        }
    }

    if (totalCount >= 3) {
        tracker->Alerted = 1;
        KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
        DbgPrint("ZETA: SilverFox sending %d paths for user-mode signature check (PID=%lu)\n", totalCount, Pid);
        // Send full path list for user-mode signature check
        SendMessageToUser(ZETA_MSG_SILVERFOX_SIGNATURE, Pid, msgBuf, written * sizeof(WCHAR));
        return TRUE; // Signal caller to block this release
    }

    KeReleaseSpinLock(&g_SilverFoxLock, oldIrql);
    return FALSE; // Not enough data or alert already sent
}
static BOOLEAN IsHoneyToken(PUNICODE_STRING Path) {
 if (!Path || !Path->Buffer) return FALSE;
 if (WildcardMatch(L"*ZETA_Honey*", Path->Buffer, Path->Length) ||
 WildcardMatch(L"*Backup_Secret*", Path->Buffer, Path->Length)) {
 return TRUE;
 }
 return FALSE;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 // P1-1: 文件保护模块开关 - 关闭时跳过所有文件保护检查
 if (!g_FileProtectEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// ── Three-tier trust check ──
	// SYSTEM:  Windows system / ZETA → skip ALL checks
	// SIGNED:  CA-signed / trusted → monitoring only (EDR scores, no blocking)
	// NONE:    Self-signed / unsigned → full HIPS blocking + EDR
	HANDLE Pid = PsGetCurrentProcessId();
	TRUST_LEVEL trustLevel = GetProcessTrustLevel(Pid);
	if (trustLevel == TRUST_LEVEL_SYSTEM) {
	 return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNICODE_STRING FileName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Pre-declare vars needed after goto (to avoid MSVC C2362)
	BOOLEAN isUntrusted = (trustLevel == TRUST_LEVEL_NONE);
	ZETA_IRP_CONTEXT irpCtx;
	RtlZeroMemory(&irpCtx, sizeof(irpCtx));
	ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
	BOOLEAN IsCreateAction = (CreateDisposition == FILE_CREATE ||
		CreateDisposition == FILE_SUPERSEDE ||
		CreateDisposition == FILE_OVERWRITE ||
		CreateDisposition == FILE_OVERWRITE_IF ||
		CreateDisposition == FILE_OPEN_IF);

	// [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
 // 部分 IRP 类型在 FltGetFileNameInformation 访问 Iopb->TargetFileObject->
 // FsContext 时可能出现 UAF（FILE_OBJECT 已被释放但仍被 Iopb 引用），
 // 捕获异常后可安全跳过文件名解析。
 __try {
     status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
 } __except (EXCEPTION_EXECUTE_HANDLER) {
     DbgPrint("ZETA: PreCreate EXCEPTION in FltGetFileNameInformation\n");
     return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 if (!NT_SUCCESS(status) || !nameInfo) {
 DbgPrint("ZETA: PreCreate FAILED to get file name info (0x%08X)\n", status);
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 status = FltParseFileNameInformation(nameInfo);
 if (!NT_SUCCESS(status)) {
 DbgPrint("ZETA: PreCreate FAILED to parse file name info (0x%08X)\n", status);
 FltReleaseFileNameInformation(nameInfo);
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 FileName = nameInfo->Name;
 if (!FileName.Buffer || FileName.Length == 0) {
 DbgPrint("ZETA: PreCreate empty file name\n");
 FltReleaseFileNameInformation(nameInfo);
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 // Compute IRP semantic context now that FileName is available
 ExtractFileSemantics_PreCreate(Data, &FileName, &irpCtx);

 // Audit mode: record full IRP details to ring buffer
 if (g_AuditMode >= AUDIT_MODE_ON) {
     ZETA_IRP_AUDIT_EXT auditExt;
     FillAuditExt_PreCreate(Data, &auditExt);
     AuditRing_WriteEntry(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length,
         &irpCtx, &auditExt);
 }

 // Learning mode: don't block anything, but still send events to user-mode
 // so the EDR engine can build baselines. This is actual "learning" behavior:
 // we observe what untrusted processes do without interfering.
 if (g_LearningModeActive) {
     DbgPrint("ZETA: LEARNING MODE - observing PID=%lu (no blocking)\n", Pid);
     // Always run lineage tracker
     LineageTracker_OnFileRelease((ULONG)(ULONG_PTR)Pid, &FileName);

     // In learning mode, we still check trust level and send learning events
     // to user-mode for EDR baseline building. No blocking, no HIPS prompts.
     if (trustLevel == TRUST_LEVEL_NONE || trustLevel == TRUST_LEVEL_SIGNED) {
         // Check protected path rules and send learning event
         if (CheckProtectedPathRule(&FileName)) {
             SendMessageToUser(2011, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
         }
         // Check hidden file (common malware indicator)
         ULONG cd = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
         BOOLEAN isCreate = (cd == FILE_CREATE || cd == FILE_SUPERSEDE ||
                             cd == FILE_OVERWRITE || cd == FILE_OVERWRITE_IF);
         if (isCreate && (Data->Iopb->Parameters.Create.FileAttributes & FILE_ATTRIBUTE_HIDDEN)) {
             SendMessageToUser(2012, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
         }
     }

     callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
     goto cleanup;
 }

 // --- MONITOR-ONLY MODE ---
 // PreCreate no longer blocks file operations. It only reports and tracks.
 // This ensures installations (even from unsigned/self-signed installers)
 // proceed at full speed without being slowed down by HIPS prompts.

 if (IsHoneyToken(&FileName)) {
  if (isUntrusted) {
  if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | DELETE)) || IsCreateAction) {
  DbgPrint("ZETA: ALERT honey token access by PID=%lu: %wZ (monitoring only)\n", Pid, &FileName);
  SendMessageToUser(7000, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
  }
  }
  }

  if (WildcardMatch(L"\\Device\\PhysicalDrive*", FileName.Buffer, FileName.Length) ||
  (WildcardMatch(L"\\Device\\Harddisk*", FileName.Buffer, FileName.Length) && !WildcardMatch(L"*Volume*", FileName.Buffer, FileName.Length))) {

  if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
  (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)) {

  if (isUntrusted) {
  DbgPrint("ZETA: ALERT disk write by PID=%lu: %wZ (monitoring only)\n", Pid, &FileName);
  UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Disk_Wiper_Attempt");
  SendMessageToUser(7000, (ULONG)(ULONG_PTR)Pid, MsgStr.Buffer, MsgStr.Length);
  }
  }
  }

  if (CheckProtectedPathRule(&FileName)) {
		DbgPrint("ZETA: PreCreate PID=%lu path MATCHED protected rule: %wZ\n", Pid, &FileName);
		if (trustLevel != TRUST_LEVEL_SYSTEM) {
  if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
  (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | GENERIC_WRITE)) || IsCreateAction) {
  DbgPrint("ZETA: ALERT protected path write by PID=%lu: %wZ\n", Pid, &FileName);
  // BYOVD defense: unsigned process writing ANY .sys file → auto-deny
              // Drivers can be loaded from any path via ZwLoadDriver. An unsigned
              // process writing .sys anywhere is 100% BYOVD - block without prompt.
              if (isUntrusted && FileName.Length >= (sizeof(WCHAR) * 5)) {
                  // Check if file extension is .sys (case-insensitive)
                  WCHAR* buf = FileName.Buffer;
                  SIZE_T len = FileName.Length / sizeof(WCHAR);
                  if ((buf[len-4] | 0x20) == L'.' &&
                      (buf[len-3] | 0x20) == L's' &&
                      (buf[len-2] | 0x20) == L'y' &&
                      (buf[len-1] | 0x20) == L's') {
                      DbgPrint("ZETA: BYOVD blocked - unsigned PID=%lu writing .sys: %wZ\n", Pid, &FileName);
                      SendMessageToUserWithContext(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length, &irpCtx);
                      Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                      Data->IoStatus.Information = 0;
                      callbackStatus = FLT_PREOP_COMPLETE;
                      goto cleanup;
                  }
                  // ── GRADUATED RESPONSE BY FILE TYPE ──
                  // HIGH risk (PE: .exe/.dll/.ocx/.scr) → HIPS popup
                  // LOW/MEDIUM risk (.txt/.log/.dat/.tmp etc.) → silent allow + EDR score
                  if (isUntrusted) {
                      if (IsPEExtension(&FileName)) {
                          // HIGH RISK: PE files → HIPS user prompt
                          if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 2001, FileName.Buffer, FileName.Length))) {
                              SendMessageToUserWithContext(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length, &irpCtx);
                              callbackStatus = FLT_PREOP_PENDING;
                              goto cleanup;
                          } else {
                              DbgPrint("ZETA: PendOperation failed - allowing access (no user-mode client)\n");
                              // Fall through → FLT_PREOP_SUCCESS_NO_CALLBACK
                          }
                      } else {
                          // LOW/MEDIUM RISK: non-PE files → silent allow + EDR
                          DbgPrint("ZETA: Allowed non-PE file by PID=%lu: %wZ\n", Pid, &FileName);
                          SendMessageToUserWithContext(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length, &irpCtx);
                          // Fall through → FLT_PREOP_SUCCESS_NO_CALLBACK
                      }
                  }
              }
  }
  }
  }

 // SilverFox: track signature status of released files
 // CheckSilverFoxPattern returns TRUE when it detects 银狐 pattern:
 // 3+ PE files released by same untrusted process → should pend & check signature
 if (isUntrusted && IsCreateAction) {
     BOOLEAN isSilverFox = CheckSilverFoxPattern((ULONG)(ULONG_PTR)Pid, &FileName);
     if (isSilverFox) {
         DbgPrint("ZETA: SilverFox | PID=%lu pattern detected, pending operation\n", Pid);
         if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 2001, FileName.Buffer, FileName.Length))) {
             SendMessageToUserWithContext(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length, &irpCtx);
             callbackStatus = FLT_PREOP_PENDING;
             goto cleanup;
         } else {
             DbgPrint("ZETA: SilverFox | PendOperation failed - allowing access\n", Pid);
         }
     }
     // Track lineage for all untrusted file creations
     LineageTracker_OnFileRelease((ULONG)(ULONG_PTR)Pid, &FileName);

     // Record PE files for rollback (delete when process exits)
     if (IsPEExtension(&FileName)) {
         Rollback_RecordFile((ULONG)(ULONG_PTR)Pid, &FileName);
     }
 }

 // ── Global hidden file defense ──
 // Only PE executables (.exe/.dll/.scr/.ocx) trigger auto-kill when hidden.
 // Non-PE hidden files (.tmp/.dat/.log/.cfg/.json etc.) are legitimate temp
 // data created by editors, IDEs, and office apps → allow silently.
 // Signed software that uses hidden files (e.g. security products) passes the
 // isUntrusted check and is skipped.
 if (isUntrusted && IsCreateAction &&
     (Data->Iopb->Parameters.Create.FileAttributes & FILE_ATTRIBUTE_HIDDEN)) {
     if (IsPEExtension(&FileName)) {
         DbgPrint("ZETA: HIDDEN PE FILE - unsigned PID=%lu creating hidden PE: %wZ\n", Pid, &FileName);
         SendMessageToUser(2002, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
         Data->IoStatus.Status = STATUS_ACCESS_DENIED;
         Data->IoStatus.Information = 0;
         callbackStatus = FLT_PREOP_COMPLETE;
         goto cleanup;
     } else {
         // Non-PE hidden file (tmp, dat, etc.) → legitimate app behavior, allow
         DbgPrint("ZETA: HIDDEN non-PE file - allowing PID=%lu: %wZ\n", Pid, &FileName);
     }
 }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

// ============================================================================
// Simple File Rollback Tracker
// Records PE files created by untrusted processes.
// When the process exits, all recorded files are deleted.
// ============================================================================

ROLLBACK_TRACKER g_RollbackTrackers[ROLLBACK_MAX_PIDS] = {0};
KSPIN_LOCK g_RollbackLock = {0};

static ROLLBACK_TRACKER* Rollback_FindOrCreateSlot(ULONG ProcessId) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RollbackLock, &OldIrql);

    // Find existing slot for this PID
    for (ULONG i = 0; i < ROLLBACK_MAX_PIDS; i++) {
        if (g_RollbackTrackers[i].ProcessId == (LONG)ProcessId) {
            KeReleaseSpinLock(&g_RollbackLock, OldIrql);
            return &g_RollbackTrackers[i];
        }
    }

    // Find free slot (ProcessId == 0 means free, PID 0 = Idle, never tracked)
    for (ULONG i = 0; i < ROLLBACK_MAX_PIDS; i++) {
        if (g_RollbackTrackers[i].ProcessId == 0) {
            g_RollbackTrackers[i].ProcessId = (LONG)ProcessId;
            g_RollbackTrackers[i].FileCount = 0;
            g_RollbackTrackers[i].WasHipsTerminated = FALSE;
            KeQuerySystemTime(&g_RollbackTrackers[i].StartTime);
            KeReleaseSpinLock(&g_RollbackLock, OldIrql);
            return &g_RollbackTrackers[i];
        }
    }

    // Overwrite oldest slot if all full
    ULONG oldest = 0;
    for (ULONG i = 1; i < ROLLBACK_MAX_PIDS; i++) {
        if (g_RollbackTrackers[i].StartTime.QuadPart < g_RollbackTrackers[oldest].StartTime.QuadPart) {
            oldest = i;
        }
    }
    g_RollbackTrackers[oldest].ProcessId = (LONG)ProcessId;
    g_RollbackTrackers[oldest].FileCount = 0;
    g_RollbackTrackers[oldest].WasHipsTerminated = FALSE;
    KeQuerySystemTime(&g_RollbackTrackers[oldest].StartTime);
    KeReleaseSpinLock(&g_RollbackLock, OldIrql);
    return &g_RollbackTrackers[oldest];
}

// Mark a process as terminated by HIPS.
// Called from user-mode via port message before process termination.
VOID Rollback_MarkTerminated(ULONG ProcessId) {
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;
    if (ProcessId == 0) return;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RollbackLock, &OldIrql);

    for (ULONG i = 0; i < ROLLBACK_MAX_PIDS; i++) {
        if (g_RollbackTrackers[i].ProcessId == (LONG)ProcessId) {
            g_RollbackTrackers[i].WasHipsTerminated = TRUE;
            DbgPrint("ZETA: Rollback - marked PID=%lu as HIPS-terminated\n", ProcessId);
            break;
        }
    }

    KeReleaseSpinLock(&g_RollbackLock, OldIrql);
}

// Record a file path for potential rollback when the process exits.
// Only PE files from untrusted processes should be recorded.
VOID Rollback_RecordFile(ULONG ProcessId, PUNICODE_STRING FilePath) {
    if (!FilePath || !FilePath->Buffer || FilePath->Length == 0) return;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;
    if (ProcessId == 0 || ProcessId == 4) return;

    ROLLBACK_TRACKER* tracker = Rollback_FindOrCreateSlot(ProcessId);
    if (!tracker) return;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RollbackLock, &OldIrql);

    if (tracker->FileCount >= ROLLBACK_MAX_FILES) {
        KeReleaseSpinLock(&g_RollbackLock, OldIrql);
        DbgPrint("ZETA: Rollback - PID=%lu file list full (%d)\n", ProcessId, ROLLBACK_MAX_FILES);
        return;
    }

    SIZE_T copyLen = FilePath->Length / sizeof(WCHAR);
    if (copyLen >= MAX_PATH_LEN) copyLen = MAX_PATH_LEN - 1;

    RtlCopyMemory(tracker->Files[tracker->FileCount].Path, FilePath->Buffer, copyLen * sizeof(WCHAR));
    tracker->Files[tracker->FileCount].Path[copyLen] = L'\0';
    tracker->FileCount++;

    KeReleaseSpinLock(&g_RollbackLock, OldIrql);
}

VOID Rollback_Execute(ULONG ProcessId) {
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;
    if (ProcessId == 0) return;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RollbackLock, &OldIrql);

    ROLLBACK_TRACKER* tracker = NULL;
    for (ULONG i = 0; i < ROLLBACK_MAX_PIDS; i++) {
        if (g_RollbackTrackers[i].ProcessId == (LONG)ProcessId) {
            tracker = &g_RollbackTrackers[i];
            break;
        }
    }

    if (!tracker || tracker->FileCount == 0) {
        KeReleaseSpinLock(&g_RollbackLock, OldIrql);
        return;
    }

    if (!tracker->WasHipsTerminated) {
        tracker->ProcessId = 0;
        tracker->FileCount = 0;
        tracker->WasHipsTerminated = FALSE;
        RtlZeroMemory(tracker->Files, sizeof(tracker->Files));
        KeReleaseSpinLock(&g_RollbackLock, OldIrql);
        DbgPrint("ZETA: Rollback - PID=%lu exited normally\n", ProcessId);
        return;
    }

    LONG count = tracker->FileCount;

    WCHAR pathBuf[MAX_PATH_LEN];
    LONG deleteCount = 0;

    for (LONG i = 0; i < count; i++) {
        RtlCopyMemory(pathBuf, tracker->Files[i].Path, sizeof(pathBuf));
        KeReleaseSpinLock(&g_RollbackLock, OldIrql);

        UNICODE_STRING uniPath;
        RtlInitUnicodeString(&uniPath, pathBuf);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &uniPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        NTSTATUS status = ZwDeleteFile(&objAttr);
        if (NT_SUCCESS(status)) {
            deleteCount++;
        } else if (status == STATUS_SHARING_VIOLATION) {
            DbgPrint("ZETA: Rollback - sharing violation: %wZ\n", &uniPath);
        } else if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_NO_SUCH_FILE) {
            DbgPrint("ZETA: Rollback - failed (0x%08X): %wZ\n", status, &uniPath);
        }

        KeAcquireSpinLock(&g_RollbackLock, &OldIrql);
    }

    tracker->ProcessId = 0;
    tracker->FileCount = 0;
    tracker->WasHipsTerminated = FALSE;
    RtlZeroMemory(tracker->Files, sizeof(tracker->Files));

    KeReleaseSpinLock(&g_RollbackLock, OldIrql);

    DbgPrint("ZETA: Rollback - PID=%lu HIPS-terminated, deleted %ld of %ld files\n", ProcessId, deleteCount, count);
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 // P1-1: 文件保护模块开关 - 关闭时跳过所有文件保护检查
 if (!g_FileProtectEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

 // P0: 也支持 FileDispositionInformationEx（Windows 10+ 新增）
 if (infoClass != FileDispositionInformation &&
     infoClass != FileDispositionInformationEx &&
     infoClass != FileRenameInformation &&
     infoClass != FileRenameInformationEx) {
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
 NTSTATUS status = STATUS_UNSUCCESSFUL;

 // [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
 __try {
     status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
 } __except (EXCEPTION_EXECUTE_HANDLER) {
     DbgPrint("ZETA: PreSetInfo EXCEPTION in FltGetFileNameInformation\n");
     goto cleanup;
 }

 HANDLE Pid = PsGetCurrentProcessId();

    if (!NT_SUCCESS(status) || !nameInfo) goto cleanup;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) goto cleanup;

    // ── P0: 提取重命名/删除语义上下文 ──
    ZETA_IRP_CONTEXT irpCtx;
    ExtractFileSemantics_PreSetInfo(Data, &nameInfo->Name, &irpCtx);

    // Audit mode: record full rename/delete details to ring buffer
    if (g_AuditMode >= AUDIT_MODE_ON) {
        ZETA_IRP_AUDIT_EXT auditExt;
        FillAuditExt_PreSetInfo(Data, &auditExt);
        AuditRing_WriteEntry(2001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer,
            nameInfo->Name.Length, &irpCtx, &auditExt);
    }

    if (!IsProcessTrusted(Pid)) {
        if (CheckProtectedPathRule(&nameInfo->Name)) {
            if (NT_SUCCESS(FltLockUserBuffer(Data))) {
                if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 2001, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
                    SendMessageToUserWithContext(2001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length, &irpCtx);
                    callbackStatus = FLT_PREOP_PENDING;
                } else {
                    DbgPrint("ZETA: PendOperation failed - allowing access\n");
                }
            } else {
                DbgPrint("ZETA: FltLockUserBuffer failed - allowing access\n");
            }
            goto cleanup;
        }
    }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
	__try {
	    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	    DbgPrint("ZETA: SetSecurity EXCEPTION in FltGetFileNameInformation\n");
	    goto cleanup;
	}

	SECURITY_INFORMATION SecurityInfo = Data->Iopb->Parameters.SetSecurity.SecurityInformation;

    if (!NT_SUCCESS(status) || !nameInfo) goto cleanup;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) goto cleanup;

    if (SecurityInfo & (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) {
        if (CheckProtectedPathRule(&nameInfo->Name)) {
            HANDLE Pid = PsGetCurrentProcessId();
            if (!IsProcessTrusted(Pid)) {
                if (NT_SUCCESS(FltLockUserBuffer(Data))) {
                    if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 2001, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
                        SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
                        callbackStatus = FLT_PREOP_PENDING;
                    } else {
                        DbgPrint("ZETA: PendOperation failed - allowing access\n");
                    }
                } else {
                    DbgPrint("ZETA: FltLockUserBuffer failed - allowing access\n");
                }
                goto cleanup;
            }
        }
    }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(CompletionContext);
 UNREFERENCED_PARAMETER(FltObjects);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 // P1-1: 文件保护模块开关 - 关闭时跳过所有文件保护检查
 if (!g_FileProtectEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) {
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

 ULONG WriteLength = Data->Iopb->Parameters.Write.Length;
 if (WriteLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
 NTSTATUS status = STATUS_UNSUCCESSFUL;

 // [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
 __try {
     status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
 } __except (EXCEPTION_EXECUTE_HANDLER) {
     DbgPrint("ZETA: PreWrite EXCEPTION in FltGetFileNameInformation\n");
     goto cleanup;
 }

 if (!NT_SUCCESS(status) || !nameInfo) goto cleanup;

 status = FltParseFileNameInformation(nameInfo);
 if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) goto cleanup;

 if (CheckFileExtensionRule(&nameInfo->Name)) {
 HANDLE Pid = PsGetCurrentProcessId();

 if (!IsProcessTrusted(Pid)) {
 // PreWrite semantic context
  ZETA_IRP_CONTEXT irpCtx;
  ExtractFileSemantics_PreWrite(Data, &nameInfo->Name, &irpCtx);

  // Audit mode: record full IRP details to ring buffer
  if (g_AuditMode >= AUDIT_MODE_ON) {
      ZETA_IRP_AUDIT_EXT auditExt;
      FillAuditExt_PreWrite(Data, &auditExt);
      AuditRing_WriteEntry(2002, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer,
          nameInfo->Name.Length, &irpCtx, &auditExt);
  }

 PVOID SystemBuffer = NULL;
 PMDL Mdl = Data->Iopb->Parameters.Write.MdlAddress;

 if (!Mdl) {
 if (Data->Iopb->Parameters.Write.WriteBuffer) {
 if (NT_SUCCESS(FltLockUserBuffer(Data))) {
 Mdl = Data->Iopb->Parameters.Write.MdlAddress;
 }
 }
 }

 if (Mdl) {
 SystemBuffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);
 }

 if (RansomExp_CheckFirstWrite(Data, &nameInfo->Name, Pid, PsGetCurrentProcess(), SystemBuffer, WriteLength)) {
        // P1-状态机/勒索重定向: 重定向开关开启时, 写隔离副本 (原文件保留), 完成 IRP 返回成功
        if (g_RansomRedirectEnabled) {
            if (NT_SUCCESS(RansomExp_RedirectWrite(&nameInfo->Name, (ULONG)(ULONG_PTR)Pid, SystemBuffer, WriteLength))) {
                DbgPrint("ZETA: Ransom redirect (first-write) PID=%lu\n", (ULONG)(ULONG_PTR)Pid);
                SendMessageToUserWithContext(5002, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length, &irpCtx);
                // 完成 IRP 返回成功, 原文件不动
                Data->IoStatus.Status = STATUS_SUCCESS;
                Data->IoStatus.Information = 0;
                callbackStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
            // 重定向失败 → 回退挂起
        }
        // Ensure FltLockUserBuffer was called before pend
        if (!Data->Iopb->Parameters.Write.MdlAddress) {
            if (Data->Iopb->Parameters.Write.WriteBuffer) {
                FltLockUserBuffer(Data);
            }
        }
        if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 5002, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
            SendMessageToUserWithContext(5002, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length, &irpCtx);
            callbackStatus = FLT_PREOP_PENDING;
        } else {
            DbgPrint("ZETA: PendOperation failed - allowing access for ransomware first-write\n");
        }
    }

    if (callbackStatus == FLT_PREOP_SUCCESS_NO_CALLBACK &&
        RansomExp_CheckWrite(Data, FltObjects, &nameInfo->Name, SystemBuffer, WriteLength)) {
        // P1-状态机/勒索重定向: 重定向开关开启时, 写隔离副本 (原文件保留), 完成 IRP 返回成功
        if (g_RansomRedirectEnabled) {
            if (NT_SUCCESS(RansomExp_RedirectWrite(&nameInfo->Name, (ULONG)(ULONG_PTR)Pid, SystemBuffer, WriteLength))) {
                DbgPrint("ZETA: Ransom redirect (high-entropy) PID=%lu\n", (ULONG)(ULONG_PTR)Pid);
                SendMessageToUserWithContext(7003, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length, &irpCtx);
                Data->IoStatus.Status = STATUS_SUCCESS;
                Data->IoStatus.Information = 0;
                callbackStatus = FLT_PREOP_COMPLETE;
                goto cleanup;
            }
            // 重定向失败 → 回退挂起
        }
        // Ensure FltLockUserBuffer was called before pend
        if (!Data->Iopb->Parameters.Write.MdlAddress) {
            if (Data->Iopb->Parameters.Write.WriteBuffer) {
                FltLockUserBuffer(Data);
            }
        }
        if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 7003, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
            SendMessageToUserWithContext(7003, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length, &irpCtx);
            callbackStatus = FLT_PREOP_PENDING;
        } else {
            DbgPrint("ZETA: PendOperation failed - allowing access for ransomware write\n");
        }
    }
 }
 }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
 if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 HANDLE Pid = PsGetCurrentProcessId();
	ULONG FsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

 // / 
 if (FsControlCode == FSCTL_DISMOUNT_VOLUME ||
  FsControlCode == FSCTL_LOCK_VOLUME) {
  if (!IsProcessTrusted(Pid)) {
  UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Volume_Dismount_Attempt");
  if (NT_SUCCESS(FltLockUserBuffer(Data))) {
   if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 4001, MsgStr.Buffer, MsgStr.Length))) {
    SendMessageToUser(4001, (ULONG)(ULONG_PTR)Pid, MsgStr.Buffer, MsgStr.Length);
    return FLT_PREOP_PENDING;
   } else {
    DbgPrint("ZETA: PendOperation failed - allowing volume dismount\n");
   }
  } else {
   DbgPrint("ZETA: FltLockUserBuffer failed - allowing volume dismount\n");
  }
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

 if (FsControlCode != FSCTL_MANAGE_BYPASS_IO) {
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 PFS_BPIO_INPUT InputBuffer = (PFS_BPIO_INPUT)Data->Iopb->Parameters.FileSystemControl.Neither.InputBuffer;
 if (!InputBuffer) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 FS_BPIO_OPERATIONS Operation;

 __try {
 Operation = InputBuffer->Operation;
 }
 __except (EXCEPTION_EXECUTE_HANDLER) {
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
 NTSTATUS status = STATUS_UNSUCCESSFUL;

 if (Operation == FS_BPIO_OP_ENABLE) {
 // [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
 __try {
     status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
 } __except (EXCEPTION_EXECUTE_HANDLER) {
     DbgPrint("ZETA: FileSystemControl EXCEPTION in FltGetFileNameInformation\n");
     goto cleanup;
 }
 if (NT_SUCCESS(status) && nameInfo) {
 if (NT_SUCCESS(FltParseFileNameInformation(nameInfo))) {
 if (CheckFileExtensionRule(&nameInfo->Name) || CheckProtectedPathRule(&nameInfo->Name)) {
 Data->IoStatus.Status = STATUS_NOT_SUPPORTED;
 callbackStatus = FLT_PREOP_COMPLETE;
 }
 }
 }
 }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

// =============================================================================
// ProtectFile_PreSectionSync — 拦截内存映射执行（DLL/EXE 加载）
// IRP_MJ_ACQUIRE_FOR_SECTION_SYNC 回调
// =============================================================================
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSectionSync(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
 if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;
 if (!g_FileProtectEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 HANDLE Pid = PsGetCurrentProcessId();
 TRUST_LEVEL trustLevel = GetProcessTrustLevel(Pid);
 if (trustLevel == TRUST_LEVEL_SYSTEM) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 NTSTATUS status = STATUS_UNSUCCESSFUL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

 // [FIX-RACE] __try/__except 防止 FLTMGR 内部崩溃传播
 __try {
     status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
 } __except (EXCEPTION_EXECUTE_HANDLER) {
     DbgPrint("ZETA: SectionSync EXCEPTION in FltGetFileNameInformation\n");
     goto cleanup;
 }

 if (NT_SUCCESS(status) && nameInfo) {
  status = FltParseFileNameInformation(nameInfo);
  if (NT_SUCCESS(status)) {
   // 检查保护路径 - 若匹配则阻止映射（防止恶意 DLL 加载）
   if (CheckProtectedPathRule(&nameInfo->Name)) {
    DbgPrint("ZETA: SectionSync BLOCKED: %wZ by PID=%lu\n",
             &nameInfo->Name, (ULONG)(ULONG_PTR)Pid);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    callbackStatus = FLT_PREOP_COMPLETE;
    goto cleanup;
   }

   // 上报非 SYSTEM 进程的 EXE/DLL 加载事件
   ULONG nameLen = nameInfo->Name.Length / sizeof(WCHAR);
   if (nameLen >= 4) {
    PCWSTR ext = nameInfo->Name.Buffer + nameLen - 4;
    if (_wcsnicmp(ext, L".dll", 4) == 0 ||
        _wcsnicmp(ext, L".exe", 4) == 0 ||
        _wcsnicmp(ext, L".sys", 4) == 0) {
     USHORT msgLen = (nameInfo->Name.Length < MAX_PATH_LEN * sizeof(WCHAR))
                     ? (USHORT)nameInfo->Name.Length : (MAX_PATH_LEN * sizeof(WCHAR));
     SendMessageToUser(ZETA_MSG_LOG, (ULONG)(ULONG_PTR)Pid,
                       nameInfo->Name.Buffer, msgLen);
    }
   }
  }
 }

cleanup:
 if (nameInfo) {
  FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}