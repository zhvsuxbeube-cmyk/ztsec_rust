// cl /nologo /LD /EHsc hello.cpp /link /OUT:hello.dll user32.lib
#include "ztsec_plugin.h"
#include <cstdlib>
#include <string_view>
#include <windows.h>

static zt_emit send_evt = nullptr;

ZT_API int32_t ZT_CALL PluginOnLoad(const uint8_t *host, uint32_t host_len, zt_emit emit) {
    send_evt = emit;
    if (!host || !host_len) return 1;
    const char *h = reinterpret_cast<const char *>(host);
    const std::string_view v(h, host_len);
    if (v.find("clientId") == std::string_view::npos ||
        v.find("os") == std::string_view::npos ||
        v.find("arch") == std::string_view::npos ||
        v.find("version") == std::string_view::npos) return 1;
    if (!std::getenv("ZTSEC_CI")) {
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
