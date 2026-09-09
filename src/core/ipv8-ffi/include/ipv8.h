/* ipv8.h — IPv8+ Phase 0 FFI 契约头文件（ADR-008：仅 Phase 0 验证使用）
 *
 * ABI 与 src/core/ipv8-ffi/src/lib.rs 手工保持同步。
 * Phase 1 起跨语言通信一律走 gRPC（tonic），本头文件冻结。
 */
#ifndef IPV8_H
#define IPV8_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;   /* Rust 分配，用 ipv8_free_buf 释放 */
    uint32_t len;
} Ipv8Buf;

typedef struct {
    uint32_t src_asn;
    uint32_t src_host;
    uint16_t src_dev;
    uint16_t src_cap;
    uint8_t  src_sec;
    uint32_t dst_asn;
    uint32_t dst_host;
    uint16_t dst_dev;
    uint16_t dst_cap;
    uint8_t  dst_sec;
    uint16_t flags;
    uint16_t payload_len;
    uint8_t  hop_limit;
    uint8_t  next_header;
} Ipv8Decoded;

/* 基础包头固定 40 字节 */
#define IPV8_BASE_HEADER_SIZE 40

Ipv8Buf ipv8_encode(uint32_t src_asn, uint32_t src_host, uint16_t src_dev,
                    uint16_t src_cap, uint8_t src_sec,
                    uint32_t dst_asn, uint32_t dst_host, uint16_t dst_dev,
                    uint16_t dst_cap, uint8_t dst_sec,
                    uint16_t flags, uint8_t hop_limit,
                    const uint8_t *payload, uint32_t payload_len);

/* 返回 0 成功；-1 空指针；-2 解码失败 */
int32_t ipv8_decode(const uint8_t *buf, uint32_t len, Ipv8Decoded *out);

uint32_t ipv8_base_header_size(void);

void ipv8_free_buf(uint8_t *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* IPV8_H */
