#ifndef ZTSEC_PLUGIN_H
#define ZTSEC_PLUGIN_H

#include <stdint.h>

#ifdef _WIN32
#define ZT_API __declspec(dllexport)
#define ZT_CALL __cdecl
#else
#define ZT_API
#define ZT_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (ZT_CALL *zt_emit)(const uint8_t *event, uint32_t event_len,
                                   const uint8_t *payload, uint32_t payload_len);

ZT_API int32_t ZT_CALL PluginOnLoad(const uint8_t *host, uint32_t host_len, zt_emit emit);
ZT_API int32_t ZT_CALL PluginOnEvent(const uint8_t *event, uint32_t event_len,
                                     const uint8_t *payload, uint32_t payload_len);
ZT_API void ZT_CALL PluginOnUnload(void);

#ifdef __cplusplus
}
#endif

#endif
