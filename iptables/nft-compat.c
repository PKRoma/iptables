/*
 * (C) 2024 Red Hat GmbH
 * Author: Phil Sutter <phil@nwl.cc>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "config.h"
#include "nft-compat.h"
#include "nft-ruleparse.h"
#include "nft.h"

#include <stdlib.h>
#include <string.h>
#include <xtables.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include <libnftnl/udata.h>

static struct rule_udata_ext *
rule_get_udata_ext(const struct nftnl_rule *r, uint32_t *outlen)
{
	const struct nftnl_udata *tb[UDATA_TYPE_MAX + 1] = {};
	struct nftnl_udata_buf *udata;
	uint32_t udatalen;

	udata = (void *)nftnl_rule_get_data(r, NFTNL_RULE_USERDATA, &udatalen);
	if (!udata)
		return NULL;

	if (nftnl_udata_parse(udata, udatalen, parse_udata_cb, tb) < 0)
		return NULL;

	if (!tb[UDATA_TYPE_COMPAT_EXT])
		return NULL;

	if (outlen)
		*outlen = nftnl_udata_len(tb[UDATA_TYPE_COMPAT_EXT]);
	return nftnl_udata_get(tb[UDATA_TYPE_COMPAT_EXT]);
}

static struct nftnl_expr *
__nftnl_expr_from_udata_ext(struct rule_udata_ext *rue, const void *data)
{
	struct nftnl_expr *expr = NULL;

	switch (rue->flags & RUE_FLAG_TYPE_BITS) {
	case RUE_FLAG_MATCH_TYPE:
		expr = nftnl_expr_alloc("match");
		__add_match(expr, data);
		break;
	case RUE_FLAG_TARGET_TYPE:
		expr = nftnl_expr_alloc("target");
		__add_target(expr, data);
		break;
	default:
		fprintf(stderr,
			"Warning: Unexpected udata extension type %d\n",
			rue->flags & RUE_FLAG_TYPE_BITS);
	}

	return expr;
}

static struct nftnl_expr *
nftnl_expr_from_zipped_udata_ext(struct rule_udata_ext *rue)
{
#ifdef HAVE_ZLIB
	uLongf datalen = rue->orig_size;
	struct nftnl_expr *expr = NULL;
	void *data;

	data = xtables_malloc(datalen);
	if (uncompress(data, &datalen, rue->data, rue->size) != Z_OK) {
		fprintf(stderr, "Warning: Failed to uncompress rule udata extension\n");
		goto out;
	}

	expr = __nftnl_expr_from_udata_ext(rue, data);
out:
	free(data);
	return expr;
#else
	fprintf(stderr, "Warning: Zipped udata extensions are not supported.\n");
	return NULL;
#endif
}

static struct nftnl_expr *nftnl_expr_from_udata_ext(struct rule_udata_ext *rue)
{
	if (rue->flags & RUE_FLAG_ZIP)
		return nftnl_expr_from_zipped_udata_ext(rue);
	else
		return __nftnl_expr_from_udata_ext(rue, rue->data);
}

bool rule_has_udata_ext(const struct nftnl_rule *r)
{
	return rule_get_udata_ext(r, NULL) != NULL;
}

#define rule_udata_ext_foreach(rue, ext, extlen)			\
	for (rue = (void *)(ext);					\
	     (char *)rue < (char *)(ext) + extlen;			\
	     rue = (void *)((char *)rue + sizeof(*rue) + rue->size))

bool rule_parse_udata_ext(struct nft_xt_ctx *ctx, const struct nftnl_rule *r)
{
	struct rule_udata_ext *rue;
	struct nftnl_expr *expr;
	uint32_t extlen;
	bool ret = true;
	int eidx = 0;
	void *ext;

	ext = rule_get_udata_ext(r, &extlen);
	if (!ext)
		return false;

	rule_udata_ext_foreach(rue, ext, extlen) {
		for (; eidx < rue->start_idx; eidx++) {
			expr = nftnl_expr_iter_next(ctx->iter);
			if (!nft_parse_rule_expr(ctx->h, expr, ctx))
				ret = false;
		}

		expr = nftnl_expr_from_udata_ext(rue);
		if (!nft_parse_rule_expr(ctx->h, expr, ctx))
			ret = false;
		nftnl_expr_free(expr);

		for (; eidx < rue->end_idx; eidx++)
			nftnl_expr_iter_next(ctx->iter);
	}
	expr = nftnl_expr_iter_next(ctx->iter);
	while (expr != NULL) {
		if (!nft_parse_rule_expr(ctx->h, expr, ctx))
			ret = false;
		expr = nftnl_expr_iter_next(ctx->iter);
	}
	return ret;
}

