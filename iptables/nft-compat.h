#ifndef _NFT_COMPAT_H_
#define _NFT_COMPAT_H_

#include <libnftnl/rule.h>

#include <linux/netfilter/x_tables.h>

enum rule_udata_ext_flags {
	RUE_FLAG_MATCH_TYPE	= (1 << 0),
	RUE_FLAG_TARGET_TYPE	= (1 << 1),
	RUE_FLAG_ZIP		= (1 << 7),
};
#define RUE_FLAG_TYPE_BITS	(RUE_FLAG_MATCH_TYPE | RUE_FLAG_TARGET_TYPE)

struct rule_udata_ext {
	uint8_t start_idx;
	uint8_t end_idx;
	uint8_t flags;
	uint16_t orig_size;
	uint16_t size;
	unsigned char data[];
};

struct nft_xt_ctx;

bool rule_has_udata_ext(const struct nftnl_rule *r);
bool rule_parse_udata_ext(struct nft_xt_ctx *ctx, const struct nftnl_rule *r);

#endif /* _NFT_COMPAT_H_ */
