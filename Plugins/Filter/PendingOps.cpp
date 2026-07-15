#include "DriverCommon.h"

// ============================================================================
// Pending Operations Manager
// Tracks minifilter callbacks awaiting user-mode allow/deny decision
// ============================================================================

#define MAX_PENDING_OPS 64

LIST_ENTRY g_PendingOps;
KSPIN_LOCK g_PendingOpsLock;
static BOOLEAN g_PendingOpsInitialized = FALSE;
BOOLEAN g_IsUnloading = FALSE;
static const LONGLONG PENDING_TIMEOUT_100NS = -300000000LL; // 30 seconds (negative = relative)

typedef struct _PENDING_PROCESS_NODE {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    ULONG RefCount;            // number of pending ops for this process
} PENDING_PROCESS_NODE, *PPENDING_PROCESS_NODE;

static LIST_ENTRY g_PendingProcesses;
static KSPIN_LOCK g_PendingProcessesLock;

// ---------- Internal helpers ----------

static PPENDING_PROCESS_NODE FindOrCreateProcessNode(ULONG ProcessId) {
    PPENDING_PROCESS_NODE node = NULL;

    // Find existing
    for (PLIST_ENTRY entry = g_PendingProcesses.Flink; entry != &g_PendingProcesses; entry = entry->Flink) {
        PPENDING_PROCESS_NODE cur = CONTAINING_RECORD(entry, PENDING_PROCESS_NODE, ListEntry);
        if (cur->ProcessId == ProcessId) {
            return cur;
        }
    }

    // Create new
    node = (PPENDING_PROCESS_NODE)ZetaAllocate(sizeof(PENDING_PROCESS_NODE));
    if (!node) return NULL;

    node->ProcessId = ProcessId;
    node->RefCount = 0;
    InsertTailList(&g_PendingProcesses, &node->ListEntry);
    return node;
}

static VOID ReleaseProcessNode(PPENDING_PROCESS_NODE node) {
    if (!node) return;
    node->RefCount--;
    if (node->RefCount <= 0) {
        RemoveEntryList(&node->ListEntry);
        ZetaFree(node);
    }
}

// ---------- Public API ----------

VOID InitializePendingOps() {
    InitializeListHead(&g_PendingOps);
    KeInitializeSpinLock(&g_PendingOpsLock);
    InitializeListHead(&g_PendingProcesses);
    KeInitializeSpinLock(&g_PendingProcessesLock);
    g_PendingOpsInitialized = TRUE;
    DbgPrint("ZETA: PendingOps initialized\n");
}

NTSTATUS PendOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                       ULONG ProcessId, ULONG MessageCode,
                       PWCHAR TargetPath, ULONG TargetPathBytes) {
    if (!g_PendingOpsInitialized || g_IsUnloading) {
        return STATUS_UNSUCCESSFUL;
    }

    // If no user-mode client is connected, don't pend operations.
    // Without a client, pended operations would timeout and be denied,
    // which would be "silent kill" behavior - not HIPS.
    if (!GlobalData.ClientPort) {
        DbgPrint("ZETA: PendOperation SKIPPED - no user-mode client (PID=%lu Code=%lu)\n", ProcessId, MessageCode);
        // NOTE: Can't send debug log to user-mode here because ClientPort is NULL
        return STATUS_PORT_DISCONNECTED;
    }

    PPENDING_OP op = (PPENDING_OP)ZetaAllocate(sizeof(PENDING_OP));
    if (!op) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(op, sizeof(PENDING_OP));
    op->CallbackData = Data;
    op->FltObjects = FltObjects;
    op->ProcessId = ProcessId;
    op->MessageCode = MessageCode;
    KeQuerySystemTime(&op->StartTime);

    // Copy target path
    if (TargetPath && TargetPathBytes > 0) {
        ULONG copyBytes = TargetPathBytes < (MAX_PATH_LEN * sizeof(WCHAR)) ? TargetPathBytes : (MAX_PATH_LEN * sizeof(WCHAR));
        RtlCopyMemory(op->TargetPath, TargetPath, copyBytes);
        op->TargetPath[(MAX_PATH_LEN - 1)] = L'\0';
    }

    // Track process reference
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PendingProcessesLock, &oldIrql);
    PPENDING_PROCESS_NODE procNode = FindOrCreateProcessNode(ProcessId);
    if (procNode) procNode->RefCount++;
    KeReleaseSpinLock(&g_PendingProcessesLock, oldIrql);

    // Add to pending list
    KeAcquireSpinLock(&g_PendingOpsLock, &oldIrql);
    InsertTailList(&g_PendingOps, &op->ListEntry);
    KeReleaseSpinLock(&g_PendingOpsLock, oldIrql);

    DbgPrint("ZETA: PendingOp added PID=%lu Code=%lu (pending count grows)\n", ProcessId, MessageCode);
    return STATUS_SUCCESS;
}

NTSTATUS CompletePendingOperation(ULONG ProcessId, BOOLEAN Allow) {
    if (!g_PendingOpsInitialized) return STATUS_UNSUCCESSFUL;

    KIRQL oldIrql;
    PPENDING_OP found = NULL;

    // Find pending op for this PID (oldest first)
    KeAcquireSpinLock(&g_PendingOpsLock, &oldIrql);
    for (PLIST_ENTRY entry = g_PendingOps.Flink; entry != &g_PendingOps; entry = entry->Flink) {
        PPENDING_OP op = CONTAINING_RECORD(entry, PENDING_OP, ListEntry);
        if (op->ProcessId == ProcessId) {
            found = op;
            RemoveEntryList(&op->ListEntry);
            break;
        }
    }
    KeReleaseSpinLock(&g_PendingOpsLock, oldIrql);

    if (!found) {
        DbgPrint("ZETA: CompletePendingOp - no pending op found for PID=%lu\n", ProcessId);
        return STATUS_NOT_FOUND;
    }

    DbgPrint("ZETA: CompletePendingOp PID=%lu Code=%lu Allow=%s\n",
             ProcessId, found->MessageCode, Allow ? "YES" : "NO");

    // P2: Trust window — if user allowed, add to 30-min trust window
    // Uses process PATH (not PID) so all processes sharing the same
    // executable (e.g. Electron child processes) are covered.
    if (Allow) {
        WCHAR procPath[TRUST_WINDOW_PATH_LEN];
        if (GetProcessPathFromPid(ProcessId, procPath, TRUST_WINDOW_PATH_LEN)) {
            AddToTrustWindow(procPath);
            DbgPrint("ZETA: Added to trust window via path: %ws\n", procPath);
        } else {
            DbgPrint("ZETA: WARNING - Could not resolve path for PID=%lu, trust window not set\n", ProcessId);
        }
    }

    // Complete the pended operation
    if (found->CallbackData) {
        __try {
            if (Allow) {
                // Allow the operation to proceed
                found->CallbackData->IoStatus.Status = STATUS_SUCCESS;
                found->CallbackData->IoStatus.Information = 0;
                FltCompletePendedPreOperation(found->CallbackData, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
            } else {
                // Deny: block the operation
                found->CallbackData->IoStatus.Status = STATUS_ACCESS_DENIED;
                found->CallbackData->IoStatus.Information = 0;
                FltCompletePendedPreOperation(found->CallbackData, FLT_PREOP_COMPLETE, NULL);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("ZETA: CompletePendingOp - exception accessing CallbackData (PID=%lu), skipping\n", ProcessId);
        }
    }

    // Release process reference
    KIRQL procIrql;
    KeAcquireSpinLock(&g_PendingProcessesLock, &procIrql);
    for (PLIST_ENTRY entry = g_PendingProcesses.Flink; entry != &g_PendingProcesses; entry = entry->Flink) {
        PPENDING_PROCESS_NODE procNode = CONTAINING_RECORD(entry, PENDING_PROCESS_NODE, ListEntry);
        if (procNode->ProcessId == ProcessId) {
            ReleaseProcessNode(procNode);
            break;
        }
    }
    KeReleaseSpinLock(&g_PendingProcessesLock, procIrql);

    ZetaFree(found);
    return STATUS_SUCCESS;
}

VOID CleanupAllPendingOperations() {
    if (!g_PendingOpsInitialized) return;

    DbgPrint("ZETA: Cleaning up all pending operations (free memory only)\n");

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PendingOpsLock, &oldIrql);

    // Collect all pending ops to free outside the lock
    // This prevents holding spinlock during memory deallocation
    PLIST_ENTRY entries[MAX_PENDING_OPS];
    ULONG count = 0;

    while (!IsListEmpty(&g_PendingOps) && count < MAX_PENDING_OPS) {
        entries[count++] = RemoveHeadList(&g_PendingOps);
    }

    KeReleaseSpinLock(&g_PendingOpsLock, oldIrql);

    // Free outside the lock - ZetaFree may access paged memory
    for (ULONG i = 0; i < count; i++) {
        PPENDING_OP op = CONTAINING_RECORD(entries[i], PENDING_OP, ListEntry);
        ZetaFree(op);
    }

    // Clean up process nodes
    KeAcquireSpinLock(&g_PendingProcessesLock, &oldIrql);

    PLIST_ENTRY procEntries[MAX_PENDING_OPS];
    count = 0;

    while (!IsListEmpty(&g_PendingProcesses) && count < MAX_PENDING_OPS) {
        procEntries[count++] = RemoveHeadList(&g_PendingProcesses);
    }

    KeReleaseSpinLock(&g_PendingProcessesLock, oldIrql);

    for (ULONG i = 0; i < count; i++) {
        PPENDING_PROCESS_NODE node = CONTAINING_RECORD(procEntries[i], PENDING_PROCESS_NODE, ListEntry);
        ZetaFree(node);
    }

    g_PendingOpsInitialized = FALSE;

    DbgPrint("ZETA: Pending ops cleanup complete\n");
}

// Check for timed-out pending operations (called periodically or during cleanup)
VOID CheckPendingTimeouts() {
    if (!g_PendingOpsInitialized || g_IsUnloading) return;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL oldIrql;
    BOOLEAN restart;

    do {
        restart = FALSE;
        KeAcquireSpinLock(&g_PendingOpsLock, &oldIrql);

        PLIST_ENTRY entry = g_PendingOps.Flink;
        while (entry != &g_PendingOps) {
            PPENDING_OP op = CONTAINING_RECORD(entry, PENDING_OP, ListEntry);

            // Check timeout: 30 seconds
            LONGLONG elapsed = now.QuadPart - op->StartTime.QuadPart;
            if (elapsed > 300000000LL) {
                // 1. Remove from list under lock
                RemoveEntryList(entry);

                // 2. Release lock BEFORE touching op data
                KeReleaseSpinLock(&g_PendingOpsLock, oldIrql);

                // 3. Complete and free outside the lock (safe - op is removed from list)
                DbgPrint("ZETA: PendingOp TIMEOUT PID=%lu Code=%lu\n", op->ProcessId, op->MessageCode);

                if (op->CallbackData) {
                    __try {
                        op->CallbackData->IoStatus.Status = STATUS_ACCESS_DENIED;
                        op->CallbackData->IoStatus.Information = 0;
                        FltCompletePendedPreOperation(op->CallbackData, FLT_PREOP_COMPLETE, NULL);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgPrint("ZETA: PendingOp TIMEOUT - exception accessing CallbackData (PID=%lu)\n", op->ProcessId);
                    }
                }

                ZetaFree(op);

                // 4. MUST restart from head: another thread (user-mode ALLOW/DENY,
                //    CheckPendingTimeouts on timeout-thread) may have modified the
                //    list while we held no lock. Any saved "next" pointer is invalid.
                restart = TRUE;
                break;
            }

            entry = entry->Flink;
        }

        // If no node was removed, release lock and exit normally
        if (!restart) {
            KeReleaseSpinLock(&g_PendingOpsLock, oldIrql);
        }
        // Otherwise, outer do-while re-acquires lock and scans from head

    } while (restart);
}

// ============================================================================
// Deferred Work Item Support for IRQL Safety
// ============================================================================

typedef struct _COMPLETION_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    ULONG ProcessId;
    BOOLEAN Allow;
} COMPLETION_WORK_ITEM, *PCOMPLETION_WORK_ITEM;

static VOID CompletePendingOperationWorker(PVOID Parameter) {
    PCOMPLETION_WORK_ITEM workItem = (PCOMPLETION_WORK_ITEM)Parameter;
    
    // Check if we're unloading - don't complete operations during unload
    if (g_IsUnloading) {
        DbgPrint("ZETA: Skipping deferred operation - driver is unloading (PID=%lu)\n", workItem->ProcessId);
        ZetaFree(workItem);
        InterlockedDecrement(&g_WorkItemTracker.PendingCount);
        return;
    }
    
    DbgPrint("ZETA: Completing deferred operation PID=%lu Allow=%s\n", 
             workItem->ProcessId, workItem->Allow ? "YES" : "NO");
    
    // This runs at PASSIVE_LEVEL, safe to call FltCompletePendedPreOperation
    CompletePendingOperation(workItem->ProcessId, workItem->Allow);
    
    ZetaFree(workItem);
    
    // Decrement counter; if zero, signal completion event
    if (InterlockedDecrement(&g_WorkItemTracker.PendingCount) == 0) {
        KeSetEvent(&g_WorkItemTracker.CompletionEvent, 0, FALSE);
    }
}

NTSTATUS QueueCompletePendingOperation(ULONG ProcessId, BOOLEAN Allow) {
    PCOMPLETION_WORK_ITEM workItem = (PCOMPLETION_WORK_ITEM)ZetaAllocate(sizeof(COMPLETION_WORK_ITEM));
    if (!workItem) {
        DbgPrint("ZETA: QueueCompletePendingOperation - allocation failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    workItem->ProcessId = ProcessId;
    workItem->Allow = Allow;
    
    ExInitializeWorkItem(&workItem->WorkItem, CompletePendingOperationWorker, workItem);
    
    // Increment counter BEFORE queuing to ensure DriverUnload sees it immediately
    InterlockedIncrement(&g_WorkItemTracker.PendingCount);
    
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Periodic Timeout Checker Thread
// Runs every 5 seconds to clean up pending operations that have timed out.
// Without this, pending ops would accumulate indefinitely since
// CheckPendingTimeouts was previously only called during driver unload.
// ============================================================================
static HANDLE g_TimeoutThreadHandle = NULL;
static KEVENT g_TimeoutStopEvent;
static BOOLEAN g_TimeoutThreadRunning = FALSE;

static VOID TimeoutCheckerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    DbgPrint("ZETA: Timeout checker thread started\n");
    
    while (g_TimeoutThreadRunning) {
        // Wait 1 second or until stop signal (shorter interval for faster unload)
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL; // 1 second (negative = relative)
        KeWaitForSingleObject(&g_TimeoutStopEvent, Executive, KernelMode, FALSE, &timeout);
        
        // Exit immediately if unloading or stop was requested
        if (!g_TimeoutThreadRunning || g_IsUnloading) break;
        
        CheckPendingTimeouts();
    }
    
    DbgPrint("ZETA: Timeout checker thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID StartTimeoutChecker() {
    if (g_TimeoutThreadRunning) return;
    
    KeInitializeEvent(&g_TimeoutStopEvent, NotificationEvent, FALSE);
    g_TimeoutThreadRunning = TRUE;
    
    NTSTATUS status = PsCreateSystemThread(
        &g_TimeoutThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        TimeoutCheckerThread,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        DbgPrint("ZETA: Timeout checker thread created (Handle=0x%p)\n", g_TimeoutThreadHandle);
    } else {
        DbgPrint("ZETA: Failed to create timeout checker thread (0x%08X)\n", status);
        g_TimeoutThreadRunning = FALSE;
    }
}

VOID StopTimeoutChecker() {
    if (!g_TimeoutThreadRunning) return;
    
    g_TimeoutThreadRunning = FALSE;
    KeSetEvent(&g_TimeoutStopEvent, 0, FALSE);
    
    if (g_TimeoutThreadHandle) {
        PVOID threadObj = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(g_TimeoutThreadHandle, SYNCHRONIZE, NULL, KernelMode, &threadObj, NULL);
        if (NT_SUCCESS(status)) {
            KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(threadObj);
        }
        ZwClose(g_TimeoutThreadHandle);
        g_TimeoutThreadHandle = NULL;
    }
    
    DbgPrint("ZETA: Timeout checker thread stopped\n");
}

