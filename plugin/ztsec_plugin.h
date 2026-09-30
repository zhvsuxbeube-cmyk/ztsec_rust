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

/* Host/plugin event names understood by the agent transport. Plugins may use
   any other UTF-8 event name for application-specific messages. */
#define ZT_EVENT_FILE_SEND_BEGIN "file.send.begin"
#define ZT_EVENT_FILE_SEND_CHUNK "file.send.chunk"
#define ZT_EVENT_FILE_SEND_END   "file.send.end"

/* file.send.begin payload: UTF-8 "transferId|fileName|size|sha256" */
/* file.send.chunk payload: UTF-8 "transferId|offset|" followed by raw bytes */
/* file.send.end payload: UTF-8 "transferId" */

ZT_API int32_t ZT_CALL PluginOnLoad(const uint8_t *host, uint32_t host_len, zt_emit emit);
ZT_API int32_t ZT_CALL PluginOnEvent(const uint8_t *event, uint32_t event_len,
                                     const uint8_t *payload, uint32_t payload_len);
ZT_API void ZT_CALL PluginOnUnload(void);

#ifdef __cplusplus
}
#endif

#endif
