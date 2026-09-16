#include "ztsec_plugin.h"
#include <windows.h>
#include <stdint.h>

static zt_emit send_evt = nullptr;

static void emit_text(const char *event, const char *text) {
    if (!send_evt) return;
    uint32_t n = 0; while (text && text[n]) ++n;
    uint32_t e = 0; while (event && event[e]) ++e;
    send_evt(reinterpret_cast<const uint8_t *>(event), e,
             reinterpret_cast<const uint8_t *>(text ? text : ""), n);
}

static bool streq(const uint8_t *p, uint32_t n, const char *s) {
    uint32_t m = 0; while (s[m]) ++m;
    if (n != m) return false;
    for (uint32_t i = 0; i < n; ++i) if (p[i] != static_cast<uint8_t>(s[i])) return false;
    return true;
}

static void append(char *out, uint32_t cap, uint32_t &used, const char *s) {
    if (!out || used >= cap) return;
    while (*s && used + 1 < cap) out[used++] = *s++;
    out[used] = '\0';
}

static void list_drives() {
    char roots[512] = {};
    DWORD len = GetLogicalDriveStringsA(sizeof(roots) - 1, roots);
    if (!len || len >= sizeof(roots)) { emit_text("explorer.error", "GetLogicalDriveStrings failed"); return; }
    char out[8192] = {};
    uint32_t used = 0;
    for (DWORD i = 0; i < len;) {
        const char *root = roots + i;
        if (!*root) break;
        char type[32] = "Unknown";
        switch (GetDriveTypeA(root)) {
            case DRIVE_FIXED: append(out, sizeof(out), used, root); append(out, sizeof(out), used, "|Drive\n"); break;
            case DRIVE_REMOVABLE: append(out, sizeof(out), used, root); append(out, sizeof(out), used, "|Removable\n"); break;
            case DRIVE_REMOTE: append(out, sizeof(out), used, root); append(out, sizeof(out), used, "|Network\n"); break;
            default: append(out, sizeof(out), used, root); append(out, sizeof(out), used, "|Other\n"); break;
        }
        (void)type;
        i += static_cast<DWORD>(lstrlenA(root)) + 1;
    }
    emit_text("explorer.drives", out);
}

static void list_directory(const char *input) {
    char path[MAX_PATH] = {};
    if (!input || !*input || lstrlenA(input) >= MAX_PATH - 3) { emit_text("explorer.error", "Invalid path"); return; }
    lstrcpyA(path, input);
    if (path[lstrlenA(path) - 1] != '\\') lstrcatA(path, "\\");
    char pattern[MAX_PATH] = {};
    lstrcpyA(pattern, path);
    lstrcatA(pattern, "*");

    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { emit_text("explorer.error", "Directory could not be opened"); return; }

    char out[12000] = {};
    uint32_t used = 0;
    do {
        if (!lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, "..")) continue;
        append(out, sizeof(out), used, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            append(out, sizeof(out), used, "|Directory|0|");
        } else {
            ULARGE_INTEGER size; size.HighPart = fd.nFileSizeHigh; size.LowPart = fd.nFileSizeLow;
            char sizeText[32] = {};
            wsprintfA(sizeText, "%llu", static_cast<unsigned long long>(size.QuadPart));
            append(out, sizeof(out), used, "|File|");
            append(out, sizeof(out), used, sizeText);
            append(out, sizeof(out), used, "|");
        }
        append(out, sizeof(out), used, path);
        append(out, sizeof(out), used, fd.cFileName);
        append(out, sizeof(out), used, "\n");
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    emit_text("explorer.entries", out);
}

ZT_API int32_t ZT_CALL PluginOnLoad(const uint8_t *host, uint32_t host_len, zt_emit emit) {
    if (!host || host_len == 0 || !emit) return 1;
    send_evt = emit;
    emit_text("explorer.ready", "example explorer client ready");
    return 0;
}

ZT_API int32_t ZT_CALL PluginOnEvent(const uint8_t *event, uint32_t event_len,
                                     const uint8_t *payload, uint32_t payload_len) {
    if (!send_evt || !event) return 1;
    if (streq(event, event_len, "explorer") || streq(event, event_len, "ping")) {
        if (payload && payload_len == 4 && streq(payload, payload_len, "list")) {
            list_drives();
            return 0;
        }
        if (payload && payload_len > 5 && payload[0]=='l' && payload[1]=='i' && payload[2]=='s' && payload[3]=='t' && payload[4]=='|') {
            list_directory(reinterpret_cast<const char *>(payload + 5));
            return 0;
        }
    }
    emit_text("explorer.unknown", "unsupported explorer command");
    return 0;
}

ZT_API void ZT_CALL PluginOnUnload(void) { send_evt = nullptr; }
