// cl /nologo /LD /EHsc /std:c++17 hello.cpp /link /OUT:hello.dll user32.lib
#include "ztsec_plugin.h"
#include <windows.h>

static zt_emit send_evt = nullptr;

// Inline helper: find needle in [hay, hay+hay_len). No CRT dependency.
static bool contains(const char *hay, uint32_t hay_len, const char *needle) {
    uint32_t n = 0;
    while (needle[n]) ++n;
    if (n == 0 || n > hay_len) return n == 0;
    for (uint32_t i = 0; i <= hay_len - n; ++i) {
        bool ok = true;
        for (uint32_t j = 0; j < n && ok; ++j)
            ok = (hay[i + j] == needle[j]);
        if (ok) return true;
    }
    return false;
}

ZT_API int32_t ZT_CALL PluginOnLoad(const uint8_t *host, uint32_t host_len, zt_emit emit) {
    send_evt = emit;
    if (!host || !host_len) return 1;
    const char *h = reinterpret_cast<const char *>(host);
    if (!contains(h, host_len, "clientId") ||
        !contains(h, host_len, "os") ||
        !contains(h, host_len, "arch") ||
        !contains(h, host_len, "version")) return 1;
    char ci[2] = {};
    if (!GetEnvironmentVariableA("ZTSEC_CI", ci, sizeof(ci))) {
        MessageBoxA(nullptr, "Hello from ztsec agent", "ztsec plugin", MB_OK | MB_ICONINFORMATION);
    }
    if (send_evt) {
        static const char ev[] = "ready";
        static const char pl[] = "hello";
        send_evt(reinterpret_cast<const uint8_t *>(ev), 5,
                 reinterpret_cast<const uint8_t *>(pl), 5);
    }
    return 0;
}

ZT_API int32_t ZT_CALL PluginOnEvent(const uint8_t *event, uint32_t event_len,
                                     const uint8_t *, uint32_t) {
    if (send_evt) {
        static const char ev[] = "event";
        send_evt(reinterpret_cast<const uint8_t *>(ev), 5, event, event_len);
    }
    return 0;
}

ZT_API void ZT_CALL PluginOnUnload(void) {
    send_evt = nullptr;
}
