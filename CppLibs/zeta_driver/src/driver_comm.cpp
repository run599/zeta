#include "zeta_driver.h"
#include "../../zeta_core/include/zeta_core.h"
#include <Windows.h>
#include <fltuser.h>
#include <vector>

#pragma comment(lib, "fltlib.lib")

// ============================================================
// DriverComm Implementation
// ============================================================
DriverComm& DriverComm::instance() {
    static DriverComm inst;
    return inst;
}

DriverComm::DriverComm() : m_port(INVALID_HANDLE_VALUE), m_running(false) {
}

DriverComm::~DriverComm() {
    stopMessageLoop();
    disconnect();
}

bool DriverComm::connect(const std::wstring& portName) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_port != INVALID_HANDLE_VALUE) {
        printf("[ZETA_DRIVER] Already connected\n");
        return true;
    }

    HRESULT hr = FilterConnectCommunicationPort(
        portName.c_str(),
        0,
        nullptr,
        0,
        nullptr,
        &m_port);

    if (SUCCEEDED(hr)) {
        printf("[ZETA_DRIVER] FilterConnect succeeded: %S\n", portName.c_str());
        return true;
    } else {
        printf("[ZETA_DRIVER] FilterConnect FAILED: hr=0x%08lx\n", hr);
        m_port = INVALID_HANDLE_VALUE;
        return false;
    }
}

void DriverComm::disconnect() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_port != INVALID_HANDLE_VALUE) {
        CloseHandle(m_port);
        m_port = INVALID_HANDLE_VALUE;
        printf("[ZETA_DRIVER] Driver communication port closed\n");
    }
}

bool DriverComm::isConnected() {
    return m_port != INVALID_HANDLE_VALUE;
}

void DriverComm::setConnected(HANDLE port) {
    m_port = port;
}

void DriverComm::startMessageLoop() {
    if (m_running) return;
    m_running = true;
    m_messageThread = std::thread([this]() {
        printf("[ZETA_DRIVER] Message receive loop started\n");

        const size_t msgSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(ZETA_MESSAGE);
        const size_t msgSizeWithCtx = sizeof(FILTER_MESSAGE_HEADER) + sizeof(ZETA_MESSAGE) + sizeof(zeta::ZETA_IRP_CONTEXT);
        std::vector<char> buffer(msgSizeWithCtx);
        auto msgHeader = reinterpret_cast<FILTER_MESSAGE_HEADER*>(buffer.data());
        auto zetaMsg = reinterpret_cast<ZETA_MESSAGE*>(buffer.data() + sizeof(FILTER_MESSAGE_HEADER));

        int consecutiveErrors = 0;
        while (m_running) {
            ZeroMemory(buffer.data(), buffer.size());
            ULONG bytesReturned = 0;

            HRESULT hr = FilterGetMessage(
                m_port,
                msgHeader,
                static_cast<ULONG>(buffer.size()),
                nullptr);

            if (!m_running) break;

            if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                    if (m_cmdPending && m_running) {
                        drainCommandQueue();
                        consecutiveErrors = 0;
                        continue;
                    }
                    printf("[ZETA_DRIVER] Message loop aborted\n");
                    break;
                }
                if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                    break;
                }
                consecutiveErrors++;
                printf("[ZETA_DRIVER] FilterGetMessage failed (#%d): hr=0x%08lx\n", consecutiveErrors, hr);
                if (consecutiveErrors >= 5) {
                    printf("[ZETA_DRIVER] Too many errors, breaking loop\n");
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            consecutiveErrors = 0;

            unsigned long code = zetaMsg->MessageCode;
            unsigned long pid = zetaMsg->ProcessId;
            std::wstring path(zetaMsg->Path);

            // IRP 语义上下文始终跟随 ZETA_MESSAGE (内核始终发送 ZETA_MESSAGE + ZETA_IRP_CONTEXT)
            zeta::ZETA_IRP_CONTEXT irpCtx = {};
            if (buffer.size() >= sizeof(FILTER_MESSAGE_HEADER) + sizeof(ZETA_MESSAGE) + sizeof(zeta::ZETA_IRP_CONTEXT)) {
                auto ctxPtr = reinterpret_cast<zeta::ZETA_IRP_CONTEXT*>(
                    buffer.data() + sizeof(FILTER_MESSAGE_HEADER) + sizeof(ZETA_MESSAGE));
                irpCtx = *ctxPtr;
            }

            if (code != 7008 && code != 7009) {
                printf("[ZETA_DRIVER] MsgRecv: Code=%lu PID=%lu Path=%S\n",
                       code, pid, path.c_str());
            }

            auto it = m_handlers.find(code);
            if (it != m_handlers.end()) {
                try {
                    it->second(code, pid, path);
                } catch (const std::exception& e) {
                    printf("[ZETA_DRIVER] Handler exception for code %lu\n", code);
                }
            }

            if (m_externalCb) {
                try {
                    std::wstring actionType = L"unknown";
                    if (code == 2001) actionType = L"file_protect";
                    else if (code == 3001) actionType = L"registry_protect";
                    else if (code == 5001) actionType = L"ransomware";
                    else if (code == 6001) actionType = L"code_inject";
                    else if (code == 6002) actionType = L"silverfox";
                    else if (code == 6010) actionType = L"apc_inject";
                    else if (code == 7000) actionType = L"driver_log";
                    else if (code == 7001) actionType = L"lineage_alert";
                    else if (code == 7003) actionType = L"ransom_exp";
                    else if (code == 7004) actionType = L"lineage_fallback";
                    else if (code == 7006) actionType = L"process_create";
                    else if (code == 7007) actionType = L"process_exit";
                    else if (code == 7008) actionType = L"thread_create";
                    else if (code == 7009) actionType = L"thread_exit";

                    m_externalCb(code, pid, path, actionType);
                } catch (...) {}
            }

            // IRP context callback
            if (m_externalCtxCb) {
                try {
                    m_externalCtxCb(code, pid, path,
                        reinterpret_cast<const unsigned char*>(&irpCtx),
                        sizeof(zeta::ZETA_IRP_CONTEXT));
                } catch (...) {}
            }

            if (m_cmdPending) drainCommandQueue();
        }

        printf("[ZETA_DRIVER] Message receive loop ended\n");
    });
}

void DriverComm::stopMessageLoop() {
    m_running = false;
    HANDLE portToClose = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_port != INVALID_HANDLE_VALUE) {
            portToClose = m_port;
            m_port = INVALID_HANDLE_VALUE;
        }
    }
    if (portToClose != INVALID_HANDLE_VALUE) {
        CloseHandle(portToClose);
    }
    if (m_messageThread.joinable()) {
        HANDLE hNative = m_messageThread.native_handle();
        DWORD waitResult = WaitForSingleObject(hNative, 3000);
        if (waitResult == WAIT_OBJECT_0) {
            m_messageThread.join();
        } else {
            printf("[ZETA_DRIVER] Message thread did not exit within 3s, detaching\n");
            m_messageThread.detach();
        }
    }
    printf("[ZETA_DRIVER] Message loop stopped\n");
}

bool DriverComm::sendCommand(unsigned long command, const std::wstring& path,
    std::wstring* outData) {
    if (!m_running) {
        HANDLE port = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            port = m_port;
            if (port == INVALID_HANDLE_VALUE) {
                printf("[ZETA_DRIVER] SendCmd failed: Port not connected\n");
                return false;
            }
        }

        ZETA_USER_MESSAGE userMsg;
        ZeroMemory(&userMsg, sizeof(userMsg));
        userMsg.Command = command;
        wcsncpy_s(userMsg.Path, path.c_str(), _TRUNCATE);

        char reply[4096] = {0};
        ULONG replySize = sizeof(reply);

        HRESULT hr = FilterSendMessage(port, &userMsg, sizeof(userMsg),
            reply, replySize, &replySize);

        if (SUCCEEDED(hr)) {
            printf("[ZETA_DRIVER] SendCmd: cmd=%lu path=%S\n", command, path.c_str());
            if (outData && replySize > 0) {
                *outData = std::wstring(reinterpret_cast<wchar_t*>(reply), replySize / sizeof(wchar_t));
            }
            return true;
        }
        printf("[ZETA_DRIVER] SendCmd failed: cmd=%lu hr=0x%08lx\n", command, hr);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_cmdMutex);
        m_cmdQueue.push_back({command, path});
    }
    m_cmdPending = true;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_port != INVALID_HANDLE_VALUE) {
            CancelIoEx(m_port, nullptr);
        }
    }

    printf("[ZETA_DRIVER] Queued Cmd: cmd=%lu path=%S\n", command, path.c_str());
    return true;
}

void DriverComm::drainCommandQueue() {
    HANDLE port = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        port = m_port;
        if (port == INVALID_HANDLE_VALUE) return;
    }

    std::vector<std::pair<unsigned long, std::wstring>> batch;
    {
        std::lock_guard<std::mutex> lock(m_cmdMutex);
        batch.swap(m_cmdQueue);
    }
    m_cmdPending = false;

    for (auto& [cmd, path] : batch) {
        ZETA_USER_MESSAGE userMsg;
        ZeroMemory(&userMsg, sizeof(userMsg));
        userMsg.Command = cmd;
        wcsncpy_s(userMsg.Path, path.c_str(), _TRUNCATE);

        char reply[4096] = {0};
        ULONG replySize = sizeof(reply);

        HRESULT hr = FilterSendMessage(port, &userMsg, sizeof(userMsg),
            reply, replySize, &replySize);

        if (SUCCEEDED(hr)) {
            printf("[ZETA_DRIVER] SendCmd(drain): cmd=%lu path=%S\n", cmd, path.c_str());
        } else {
            printf("[ZETA_DRIVER] SendCmd(drain) failed: cmd=%lu hr=0x%08lx\n", cmd, hr);
        }
    }
}

bool DriverComm::allowOperation(unsigned long pid) {
    return sendCommand(ZETA_CMD_ALLOW_OP, std::to_wstring(pid));
}

bool DriverComm::denyOperation(unsigned long pid) {
    return sendCommand(ZETA_CMD_DENY_OP, std::to_wstring(pid));
}

bool DriverComm::markRollback(unsigned long pid) {
    return sendCommand(ZETA_CMD_ROLLBACK_MARK, std::to_wstring(pid));
}

void DriverComm::registerHandler(unsigned long code, MessageHandler handler) {
    m_handlers[code] = handler;
    printf("[ZETA_DRIVER] Registered handler for code %lu\n", code);
}

std::wstring DriverComm::getInitLog() {
    std::wstring outData;
    bool ok = sendCommand(ZETA_CMD_GET_INITLOG, L"", &outData);
    if (ok) {
        printf("[ZETA_DRIVER] GetInitLog OK\n");
    } else {
        printf("[ZETA_DRIVER] GetInitLog Failed\n");
    }
    return outData;
}

// ============================================================
// C DLL Exports
// ============================================================
extern "C" {

static void (*g_msg_callback)(unsigned long code, unsigned long pid,
    const wchar_t* path, const wchar_t* action) = nullptr;

static void internalMessageHandler(unsigned long code, unsigned long pid,
    const std::wstring& path, const std::wstring& action) {
    if (g_msg_callback) {
        g_msg_callback(code, pid, path.c_str(), action.c_str());
    }
}

__declspec(dllexport) int zeta_driver_connect(const wchar_t* portName) {
    printf("[ZETA_DRIVER] zeta_driver_connect: connecting to %S\n",
        portName ? portName : L"\\ZETA_Output_Pipe");
    
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = FilterConnectCommunicationPort(
        portName ? portName : L"\\ZETA_Output_Pipe",
        0, nullptr, 0, nullptr, &hPort);
    
    if (SUCCEEDED(hr) && hPort != INVALID_HANDLE_VALUE) {
        printf("[ZETA_DRIVER] FilterConnect succeeded, setting port handle\n");
        DriverComm::instance().setConnected(hPort);
        return 1;
    }
    
    printf("[ZETA_DRIVER] FilterConnect FAILED: hr=0x%08lx\n", hr);
    return 0;
}

__declspec(dllexport) void zeta_driver_disconnect() {
    DriverComm::instance().disconnect();
}

__declspec(dllexport) int zeta_driver_is_connected() {
    return DriverComm::instance().isConnected() ? 1 : 0;
}

// 带 IRP 上下文的全局回调
static void (*g_msg_ctx_callback)(unsigned long code, unsigned long pid,
    const wchar_t* path, const unsigned char* ctx, unsigned int ctx_size) = nullptr;

__declspec(dllexport) void zeta_driver_set_msg_ctx_callback(void* cb) {
    g_msg_ctx_callback = reinterpret_cast<void(*)(unsigned long, unsigned long,
        const wchar_t*, const unsigned char*, unsigned int)>(cb);
}

static void internalMessageHandlerCtx(unsigned long code, unsigned long pid,
    const std::wstring& path, const unsigned char* ctx, unsigned int ctx_size) {
    if (g_msg_ctx_callback) {
        g_msg_ctx_callback(code, pid, path.c_str(), ctx, ctx_size);
    }
}

__declspec(dllexport) void zeta_driver_start_loop() {
    DriverComm::instance().setExternalCallback(internalMessageHandler);
    DriverComm::instance().setExternalCtxCallback(internalMessageHandlerCtx);
    DriverComm::instance().startMessageLoop();
}

__declspec(dllexport) void zeta_driver_stop_loop() {
    DriverComm::instance().stopMessageLoop();
}

__declspec(dllexport) int zeta_driver_send_cmd(unsigned long cmd, const wchar_t* path) {
    std::wstring pathStr = path ? path : L"";
    return DriverComm::instance().sendCommand(cmd, pathStr) ? 1 : 0;
}

__declspec(dllexport) const wchar_t* zeta_driver_get_init_log() {
    static std::wstring cached;
    cached = DriverComm::instance().getInitLog();
    return cached.c_str();
}

__declspec(dllexport) void zeta_driver_set_msg_callback(void* cb) {
    g_msg_callback = reinterpret_cast<void(*)(unsigned long, unsigned long,
        const wchar_t*, const wchar_t*)>(cb);
}

__declspec(dllexport) int zeta_driver_allow_op(unsigned long pid) {
    return DriverComm::instance().allowOperation(pid) ? 1 : 0;
}

__declspec(dllexport) int zeta_driver_deny_op(unsigned long pid) {
    return DriverComm::instance().denyOperation(pid) ? 1 : 0;
}

__declspec(dllexport) void zeta_hips_reload_rules() {
    DriverComm::instance().sendCommand(ZETA_CMD_RELOAD_RULES, L"");
}

__declspec(dllexport) int zeta_driver_set_audit_mode(unsigned long mode) {
    return DriverComm::instance().setAuditMode(mode) ? 1 : 0;
}

} // extern "C"

// ============================================================
// Audit Mode API
// ============================================================
bool DriverComm::setAuditMode(unsigned long mode) {
    std::wstring path = std::to_wstring(mode);
    return sendCommand(16 /* ZETA_CMD_SET_AUDIT_MODE */, path);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            DriverComm::instance().stopMessageLoop();
            DriverComm::instance().disconnect();
            break;
    }
    return TRUE;
}
