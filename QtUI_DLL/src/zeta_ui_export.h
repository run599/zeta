#ifndef ZETA_UI_EXPORT_H
#define ZETA_UI_EXPORT_H

#ifdef __cplusplus
extern "C" {
#endif

/* DLL export macro
   加 #ifndef 守卫: 消费方 (如 ZETA.exe) 可在包含本头文件前先定义
   ZETA_API=__declspec(dllimport), 避免 C4005 宏重定义告警 */
#ifndef ZETA_API
#if defined(_MSC_VER)
    #define ZETA_API __declspec(dllexport)
#elif defined(__GNUC__)
    #define ZETA_API __attribute__((visibility("default"))) __declspec(dllexport)
#else
    #define ZETA_API __declspec(dllexport)
#endif
#endif

/* ── Callback types ──────────────────────────────────────────── */
typedef void (*zeta_config_cb)(const wchar_t* key, int value);
typedef void (*zeta_tool_cb)(const wchar_t* tool);

/* ── Lifecycle ───────────────────────────────────────────────── */
ZETA_API int  zeta_ui_init(void);
ZETA_API void zeta_ui_exec(void);
ZETA_API void zeta_ui_process_events(void);
ZETA_API void zeta_ui_shutdown(void);

/* ── Window control ──────────────────────────────────────────── */
ZETA_API void zeta_ui_show(void);
ZETA_API void zeta_ui_hide(void);
ZETA_API void zeta_ui_minimize(void);
ZETA_API void zeta_ui_restore(void);

/* ── UI updates (thread-safe) ────────────────────────────────── */
ZETA_API void zeta_ui_append_log(const wchar_t* level, const wchar_t* action, const wchar_t* detail);
ZETA_API void zeta_ui_set_theme(const wchar_t* theme_key);
ZETA_API void zeta_ui_set_driver_status(int loaded);
ZETA_API void zeta_ui_set_status_text(const wchar_t* text);
ZETA_API void zeta_ui_set_repair_item(int index, const wchar_t* status, const wchar_t* result);
ZETA_API void zeta_ui_set_repair_buttons(int enabled);
ZETA_API void zeta_ui_show_notification(const wchar_t* title, const wchar_t* message, int level);

/* ── HIPS interactive prompt ─────────────────────────────────── */
/* HIPS response callback type: called when user clicks allow/block */
typedef void (*fn_hips_response_cb)(unsigned long pid, int allow);
ZETA_API void zeta_ui_set_hips_response_callback(fn_hips_response_cb cb);
ZETA_API fn_hips_response_cb zeta_ui_get_hips_response_callback(void);
ZETA_API void zeta_ui_show_hips_prompt(const wchar_t* title, const wchar_t* message, unsigned long pid, int level);

/* ── Restore initial state ───────────────────────────────────── */
ZETA_API void zeta_ui_restore_switch(const wchar_t* key, int checked);
ZETA_API void zeta_ui_restore_combo(const wchar_t* combo_name, const wchar_t* value);

/* ── HIPS Rules management ──────────────────────────────────── */
ZETA_API void zeta_ui_set_rules_path(const wchar_t* path);

/* ── Disk filter (ZETA_DiskFilter.sys) real status ───────────── */
/* attached: 已挂接物理磁盘数  blocked: 累计拦截数  observed: 仅记录数
   mode: 0=拦截 1=仅监控   enabled: 1=防护开启
   lastInfo: 可选附加说明 (为空表示无异常) */
ZETA_API void zeta_ui_set_disk_status(int attached, int blocked, int observed,
                                      int mode, int enabled, const wchar_t* lastInfo);

/* ── Callback registration ───────────────────────────────────── */
ZETA_API void zeta_ui_set_config_callback(zeta_config_cb cb);
ZETA_API void zeta_ui_set_tool_callback(zeta_tool_cb cb);

#ifdef __cplusplus
}
#endif

#endif /* ZETA_UI_EXPORT_H */
