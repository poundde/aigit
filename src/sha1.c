#include <string.h>
#include <stdio.h>
#include "aigit.h"

/*
 * SHA-1 implementation.  We roll our own rather than pull in OpenSSL so
 * the only non-standard dependency is zlib (for object compression).
 *
 * Reference: FIPS 180-4, Section 6.1.
 */

#define ROTL32(v, n)  (((v) << (n)) | ((v) >> (32 - (n))))

struct sha1_ctx {
  uint32_t h[5];
  uint64_t bit_len;
  uint8_t  buf[64];
  size_t   buf_used;
};

static void sha1_ctx_init(struct sha1_ctx *ctx)
{
  ctx->h[0]    = 0x67452301u;
  ctx->h[1]    = 0xEFCDAB89u;
  ctx->h[2]    = 0x98BADCFEu;
  ctx->h[3]    = 0x10325476u;
  ctx->h[4]    = 0xC3D2E1F0u;
  ctx->bit_len = 0;
  ctx->buf_used = 0;
}

static void sha1_compress(struct sha1_ctx *ctx, const uint8_t block[64])
{
  uint32_t w[80];
  uint32_t a, b, c, d, e, f, k, temp;

  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i*4 + 0] << 24)
         | ((uint32_t)block[i*4 + 1] << 16)
         | ((uint32_t)block[i*4 + 2] <<  8)
         | ((uint32_t)block[i*4 + 3]);
  }
  for (int i = 16; i < 80; i++)
    w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

  a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2];
  d = ctx->h[3]; e = ctx->h[4];

  for (int i = 0; i < 80; i++) {
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999u;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1u;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCu;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6u;
    }
    temp = ROTL32(a, 5) + f + e + k + w[i];
    e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
  }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c;
  ctx->h[3] += d; ctx->h[4] += e;
}

static void sha1_ctx_update(struct sha1_ctx *ctx,
                             const uint8_t *data, size_t len)
{
  ctx->bit_len += (uint64_t)len * 8;

  while (len > 0) {
    size_t space = 64 - ctx->buf_used;
    size_t take  = len < space ? len : space;
    memcpy(ctx->buf + ctx->buf_used, data, take);
    ctx->buf_used += take;
    data          += take;
    len           -= take;

    if (ctx->buf_used == 64) {
      sha1_compress(ctx, ctx->buf);
      ctx->buf_used = 0;
    }
  }
}

static void sha1_ctx_final(struct sha1_ctx *ctx, uint8_t out[SHA1_BIN_LEN])
{
  ctx->buf[ctx->buf_used++] = 0x80;

  if (ctx->buf_used > 56) {
    while (ctx->buf_used < 64)
      ctx->buf[ctx->buf_used++] = 0;
    sha1_compress(ctx, ctx->buf);
    ctx->buf_used = 0;
  }

  while (ctx->buf_used < 56)
    ctx->buf[ctx->buf_used++] = 0;

  uint64_t bl = ctx->bit_len;
  for (int i = 7; i >= 0; i--) {
    ctx->buf[56 + i] = bl & 0xff;
    bl >>= 8;
  }
  sha1_compress(ctx, ctx->buf);

  for (int i = 0; i < 5; i++) {
    out[i*4 + 0] = (ctx->h[i] >> 24) & 0xff;
    out[i*4 + 1] = (ctx->h[i] >> 16) & 0xff;
    out[i*4 + 2] = (ctx->h[i] >>  8) & 0xff;
    out[i*4 + 3] =  ctx->h[i]        & 0xff;
  }
}

void sha1_compute(const uint8_t *data, size_t len, struct sha1 *out)
{
  struct sha1_ctx ctx;
  sha1_ctx_init(&ctx);
  sha1_ctx_update(&ctx, data, len);
  sha1_ctx_final(&ctx, out->bytes);

  for (int i = 0; i < SHA1_BIN_LEN; i++)
    snprintf(out->hex + i*2, 3, "%02x", out->bytes[i]);
  out->hex[SHA1_HEX_LEN] = '\0';
}

void sha1_hex_to_bytes(const char *hex, uint8_t *bytes)
{
  for (int i = 0; i < SHA1_BIN_LEN; i++) {
    unsigned v;
    sscanf(hex + i*2, "%02x", &v);
    bytes[i] = (uint8_t)v;
  }
}

int sha1_is_zero(const struct sha1 *sha)
{
  for (int i = 0; i < SHA1_BIN_LEN; i++)
    if (sha->bytes[i]) return 0;
  return 1;
}

void sha1_zero(struct sha1 *sha)
{
  memset(sha, 0, sizeof(*sha));
}
