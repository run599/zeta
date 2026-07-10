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

    // Learning mode: skip ALL expensive tracking, return immediately
    if (g_LearningModeActive) return FALSE;

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

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
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

 // Learning mode: skip ALL protection for first 5 minutes after boot
 // This prevents false positives during system startup and software installation
 if (g_LearningModeActive) {
     DbgPrint("ZETA: LEARNING MODE - allowing all operations for PID=%lu\n", Pid);
     // Still run lineage tracker for learning data, but don't block anything
     LineageTracker_OnFileRelease((ULONG)(ULONG_PTR)Pid, &FileName);
     callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
     goto cleanup;
 }

 BOOLEAN isUntrusted = (trustLevel == TRUST_LEVEL_NONE);
 ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
 BOOLEAN IsCreateAction = (CreateDisposition == FILE_CREATE ||
 CreateDisposition == FILE_SUPERSEDE ||
 CreateDisposition == FILE_OVERWRITE ||
 CreateDisposition == FILE_OVERWRITE_IF ||
 CreateDisposition == FILE_OPEN_IF);

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
                      SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
                      Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                      Data->IoStatus.Information = 0;
                      callbackStatus = FLT_PREOP_COMPLETE;
                      goto cleanup;
                  }
                  // Other files → pend for HIPS user prompt
                  // If pend fails (no user-mode client, etc.), allow the operation
                  // rather than blocking (which would break legitimate software).
                  // Only .sys files are unconditionally blocked (BYOVD defense).
                  if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 2001, FileName.Buffer, FileName.Length))) {
                      SendMessageToUser(2001, (ULONG)(ULONG_PTR)Pid, FileName.Buffer, FileName.Length);
                      callbackStatus = FLT_PREOP_PENDING;
                      goto cleanup;
                  } else {
                      DbgPrint("ZETA: PendOperation failed - allowing access (no user-mode client)\n");
                      // Fall through → FLT_PREOP_SUCCESS_NO_CALLBACK
                  }
              }
  }
  }
  }

 // SilverFox: track signature status of released files (monitoring only)
 if (isUntrusted && IsCreateAction) {
     BOOLEAN isSigned = CheckSilverFoxPattern((ULONG)(ULONG_PTR)Pid, &FileName);
     if (isSigned) {
         DbgPrint("ZETA: SilverFox | PID=%lu has valid signature - skipping detection\n", Pid);
     }
     // Track lineage for all untrusted file creations
     LineageTracker_OnFileRelease((ULONG)(ULONG_PTR)Pid, &FileName);
 }

cleanup:
 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

 if (infoClass != FileDispositionInformation &&
 infoClass != FileRenameInformation &&
 infoClass != FileRenameInformationEx) {
 return FLT_PREOP_SUCCESS_NO_CALLBACK;
 }

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
 NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

 HANDLE Pid = PsGetCurrentProcessId();

    if (!NT_SUCCESS(status) || !nameInfo) goto cleanup;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) goto cleanup;

    if (!IsProcessTrusted(Pid)) {
        if (CheckProtectedPathRule(&nameInfo->Name)) {
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
	NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

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

	if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) {
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

 ULONG WriteLength = Data->Iopb->Parameters.Write.Length;
 if (WriteLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
 FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
 NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

 if (!NT_SUCCESS(status) || !nameInfo) goto cleanup;

 status = FltParseFileNameInformation(nameInfo);
 if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer) goto cleanup;

 if (CheckFileExtensionRule(&nameInfo->Name)) {
 HANDLE Pid = PsGetCurrentProcessId();

 if (!IsProcessTrusted(Pid)) {
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
        // Ensure FltLockUserBuffer was called before pend
        if (!Data->Iopb->Parameters.Write.MdlAddress) {
            if (Data->Iopb->Parameters.Write.WriteBuffer) {
                FltLockUserBuffer(Data);
            }
        }
        if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 5002, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
            SendMessageToUser(5002, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
            callbackStatus = FLT_PREOP_PENDING;
        } else {
            DbgPrint("ZETA: PendOperation failed - allowing access for ransomware first-write\n");
        }
    }

    if (callbackStatus == FLT_PREOP_SUCCESS_NO_CALLBACK &&
        RansomExp_CheckWrite(Data, FltObjects, &nameInfo->Name, SystemBuffer, WriteLength)) {
        // Ensure FltLockUserBuffer was called before pend
        if (!Data->Iopb->Parameters.Write.MdlAddress) {
            if (Data->Iopb->Parameters.Write.WriteBuffer) {
                FltLockUserBuffer(Data);
            }
        }
        if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 7003, nameInfo->Name.Buffer, nameInfo->Name.Length))) {
            SendMessageToUser(7003, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
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

 if (Operation == FS_BPIO_OP_ENABLE) {
 if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) && nameInfo) {
 if (NT_SUCCESS(FltParseFileNameInformation(nameInfo))) {
 if (CheckFileExtensionRule(&nameInfo->Name) || CheckProtectedPathRule(&nameInfo->Name)) {
 Data->IoStatus.Status = STATUS_NOT_SUPPORTED;
 callbackStatus = FLT_PREOP_COMPLETE;
 }
 }
 }
 }

 if (nameInfo) {
 FltReleaseFileNameInformation(nameInfo);
 }
 return callbackStatus;
}