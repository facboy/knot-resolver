#!/bin/sh -e

### Dev's guide
#
# C declarations for lua are (mostly) generated to simplify maintenance.
# (Avoid typos, accidental mismatches, etc.)
#
# To regenerate the C definitions for lua:
# - you need to have debugging symbols for knot-dns and kresd;
#   you get those by compiling with -g; for knot-dns it might be enough
#   to just install it with debugging symbols included (in your distro way)
# - remove file ./kres-gen.lua and run make as usual
# - the knot-dns libraries are found via pkg-config
# - you also need gdb on $PATH


printf -- "local ffi = require('ffi')\n"
printf -- "--[[ This file is generated by ./kres-gen.sh ]] ffi.cdef[[\n"

## Various types (mainly), from libknot and libkres

printf "
typedef struct knot_dump_style knot_dump_style_t;
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;
"

# The generator doesn't work well with typedefs of functions.
printf "
typedef struct knot_mm {
	void *ctx, *alloc, *free;
} knot_mm_t;

typedef void *(*map_alloc_f)(void *, size_t);
typedef void (*map_free_f)(void *baton, void *ptr);
typedef void (*trace_log_f) (const struct kr_query *, const char *, const char *);
typedef void (*trace_callback_f)(struct kr_request *);
"

./scripts/gen-cdefs.sh libkres types <<-EOF
	knot_section_t
	knot_rrinfo_t
	knot_dname_t
	knot_rdata_t
	knot_rdataset_t
	struct knot_rdataset
	knot_rrset_t
	knot_pktsection_t
	struct knot_pkt
	knot_pkt_t
	# generics
	map_t
	# libkres
	struct kr_qflags
	rr_array_t
	struct ranked_rr_array_entry
	ranked_rr_array_entry_t
	ranked_rr_array_t
	struct kr_zonecut
	kr_qarray_t
	struct kr_rplan
	struct kr_request
	enum kr_rank
EOF

genResType() {
	echo "$1" | ./scripts/gen-cdefs.sh libkres types
}

# No simple way to fixup this rename in ./kres.lua AFAIK.
genResType "struct knot_rrset" | sed 's/\<owner\>/_owner/'

## Some definitions would need too many deps, so shorten them.

genResType "struct kr_nsrep" | sed '/union/,$ d'
printf "\t/* beware: hidden stub */\n};\n"

genResType "struct kr_query"

genResType "struct kr_context" | sed '/struct kr_cache/,$ d'
printf "\tchar _stub[];\n};\n"

## libknot API
./scripts/gen-cdefs.sh libknot functions <<-EOF
# Domain names
	knot_dname_from_str
	knot_dname_is_equal
	knot_dname_is_sub
	knot_dname_labels
	knot_dname_size
	knot_dname_to_str
# Resource records
	knot_rdata_rdlen
	knot_rdata_data
	knot_rdata_array_size
	knot_rdataset_at
	knot_rrset_add_rdata
	knot_rrset_init_empty
	knot_rrset_ttl
	knot_rrset_txt_dump
	knot_rrset_txt_dump_data
	knot_rrsig_sig_expiration
	knot_rrsig_sig_inception
# Packet
	knot_pkt_qname
	knot_pkt_qtype
	knot_pkt_qclass
	knot_pkt_begin
	knot_pkt_put_question
	knot_pkt_rr
	knot_pkt_section
EOF

## libkres API
./scripts/gen-cdefs.sh libkres functions <<-EOF
# Resolution request
	kr_resolve_plan
	kr_resolve_pool
# Resolution plan
	kr_rplan_push
	kr_rplan_pop
	kr_rplan_resolved
# Nameservers
	kr_nsrep_set
# Utils
	kr_rand_uint
	kr_pkt_make_auth_header
	kr_pkt_put
	kr_pkt_recycle
	kr_inaddr
	kr_inaddr_family
	kr_inaddr_len
	kr_straddr_family
	kr_straddr_subnet
	kr_bitcmp
	kr_family_len
	kr_straddr_socket
	kr_ranked_rrarray_add
	kr_qflags_set
	kr_qflags_clear
	kr_zonecut_add
	kr_zonecut_set
	kr_now
# Trust anchors
	kr_ta_get
	kr_ta_add
	kr_ta_del
	kr_ta_clear
# DNSSEC
	kr_dnssec_key_ksk
	kr_dnssec_key_revoked
	kr_dnssec_key_tag
	kr_dnssec_key_match
EOF

printf "]]\n"

exit 0
