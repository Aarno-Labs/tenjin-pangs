# M5.0 Gate Census

Generated from PANGS export directories.

Interpretation:

- `known_runtime_writer` is the strongest M5a candidate bucket: a flow-sensitive
  summary pass could potentially separate init-time writes from post-publish writes.
- `incomplete_initval` may include B1 poisoning, but it first needs source audit;
  M5a should not be green-lit from this count alone.
- `unknown_runtime_writer` and `exported_global` are not M5a wins without earlier
  boundary/modeling improvements.

## Summary

| row | mutable | rewritable | frozen | known runtime writer | incomplete initval | unknown runtime writer | exported | stationary | M5a gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `exe-chibicc-O1` | 133 | 0 | 133 | 0 | 133 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-curl-O1` | 80 | 16 | 64 | 0 | 80 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-gifsicle-O1` | 93 | 1 | 92 | 0 | 93 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-jpegoptim-O1` | 48 | 0 | 48 | 0 | 48 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-jq-O1` | 14 | 5 | 9 | 0 | 14 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-lua-O1` | 5 | 0 | 5 | 0 | 5 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-tmux-O1` | 107 | 0 | 107 | 0 | 107 | 0 | 0 | 0 | audit_incomplete_initval |
| `lib-parson-O1` | 5 | 4 | 1 | 0 | 5 | 0 | 0 | 0 | audit_incomplete_initval |
| **total** | 485 | 26 | 459 | 0 | 485 | 0 | 0 | 0 | audit_incomplete_initval |

## Gate Decision

M5a is not green-lit from this corpus snapshot. There are no mutable globals whose
stationarity verdict is blocked by a known `runtime_writer`, so the flow-sensitive
summary machinery in `PLAN-M5.md` would not currently target a measured population.

The dominant earlier blocker is `incomplete_initval`: every mutable global in this
census falls into that bucket. Use the Initval Diagnostics section below to distinguish
ordinary globals with no modeled pointer initializer from explicit B1 poison cases.

M5b is not green-lit by this census alone; it still requires a client that consumes
thread-confinement facts.

If the Runtime Mod Evidence section reports unknown mod rows, those rows independently
block stationarity and should be addressed before M5a flow summaries.

## Runtime Mod Evidence

| row | unknown mod rows | mutable globals with known mod rows | absence-only initval globals | absence-only without known mod |
|---|---:|---:|---:|---:|
| `exe-chibicc-O1` | 131 | 81 | 133 | 52 |
| `exe-curl-O1` | 60 | 51 | 80 | 29 |
| `exe-gifsicle-O1` | 158 | 90 | 93 | 3 |
| `exe-jpegoptim-O1` | 19 | 46 | 48 | 2 |
| `exe-jq-O1` | 402 | 8 | 14 | 6 |
| `exe-lua-O1` | 307 | 5 | 5 | 0 |
| `exe-tmux-O1` | 466 | 79 | 107 | 28 |
| `lib-parson-O1` | 97 | 5 | 5 | 0 |

## Unknown Mod Sources

| row | detail | rows |
|---|---|---:|
| `exe-chibicc-O1` | `edge:store|omega:steens_external` | 61 |
| `exe-chibicc-O1` | `edge:memcpy_dst|omega:steens_external` | 43 |
| `exe-chibicc-O1` | `stmt:memset_dst|omega:steens_external` | 24 |
| `exe-chibicc-O1` | `edge:store|omega:external_call_result` | 3 |
| `exe-curl-O1` | `edge:store|omega:steens_external` | 38 |
| `exe-curl-O1` | `edge:memcpy_dst|omega:steens_external` | 14 |
| `exe-curl-O1` | `stmt:memset_dst|omega:steens_external` | 4 |
| `exe-curl-O1` | `edge:store|omega:unknown` | 2 |
| `exe-curl-O1` | `edge:store|omega:external_call_result` | 2 |
| `exe-gifsicle-O1` | `edge:store|omega:steens_external` | 71 |
| `exe-gifsicle-O1` | `edge:memcpy_dst|omega:steens_external` | 50 |
| `exe-gifsicle-O1` | `stmt:memset_dst|omega:steens_external` | 30 |
| `exe-gifsicle-O1` | `edge:store|omega:unknown` | 5 |
| `exe-gifsicle-O1` | `stmt:memset_dst|omega:unknown` | 1 |
| `exe-gifsicle-O1` | `edge:store|omega:external_call_result` | 1 |
| `exe-jpegoptim-O1` | `edge:store|omega:steens_external` | 16 |
| `exe-jpegoptim-O1` | `stmt:memset_dst|omega:steens_external` | 1 |
| `exe-jpegoptim-O1` | `edge:store|omega:unknown` | 1 |
| `exe-jpegoptim-O1` | `edge:memcpy_dst|omega:steens_external` | 1 |
| `exe-jq-O1` | `edge:store|omega:steens_external` | 288 |
| `exe-jq-O1` | `stmt:memset_dst|omega:steens_external` | 106 |
| `exe-jq-O1` | `edge:store|omega:external_call_result` | 6 |
| `exe-jq-O1` | `edge:memcpy_dst|omega:steens_external` | 2 |
| `exe-lua-O1` | `edge:store|omega:steens_external` | 283 |
| `exe-lua-O1` | `edge:memcpy_dst|omega:steens_external` | 20 |
| `exe-lua-O1` | `stmt:memset_dst|omega:steens_external` | 3 |
| `exe-lua-O1` | `edge:store|omega:external_call_result` | 1 |
| `exe-tmux-O1` | `edge:store|omega:steens_external` | 389 |
| `exe-tmux-O1` | `edge:memcpy_dst|omega:steens_external` | 30 |
| `exe-tmux-O1` | `edge:store|omega:external_call_result` | 26 |
| `exe-tmux-O1` | `stmt:memset_dst|omega:steens_external` | 16 |
| `exe-tmux-O1` | `edge:store|omega:unknown` | 5 |
| `lib-parson-O1` | `edge:store|omega:steens_external` | 76 |
| `lib-parson-O1` | `edge:memcpy_dst|omega:steens_external` | 20 |
| `lib-parson-O1` | `stmt:memset_dst|omega:steens_external` | 1 |

## Unknown Mod Omega Sources

| row | omega source | rows |
|---|---|---:|
| `exe-chibicc-O1` | `omega:steens_external` | 128 |
| `exe-chibicc-O1` | `omega:external_call_result` | 3 |
| `exe-curl-O1` | `omega:steens_external` | 56 |
| `exe-curl-O1` | `omega:unknown` | 2 |
| `exe-curl-O1` | `omega:external_call_result` | 2 |
| `exe-gifsicle-O1` | `omega:steens_external` | 151 |
| `exe-gifsicle-O1` | `omega:unknown` | 6 |
| `exe-gifsicle-O1` | `omega:external_call_result` | 1 |
| `exe-jpegoptim-O1` | `omega:steens_external` | 18 |
| `exe-jpegoptim-O1` | `omega:unknown` | 1 |
| `exe-jq-O1` | `omega:steens_external` | 396 |
| `exe-jq-O1` | `omega:external_call_result` | 6 |
| `exe-lua-O1` | `omega:steens_external` | 306 |
| `exe-lua-O1` | `omega:external_call_result` | 1 |
| `exe-tmux-O1` | `omega:steens_external` | 435 |
| `exe-tmux-O1` | `omega:external_call_result` | 26 |
| `exe-tmux-O1` | `omega:unknown` | 5 |
| `lib-parson-O1` | `omega:steens_external` | 97 |

## Steens External Mod Shape

| row | pointee shape | rows |
|---|---|---:|
| `exe-chibicc-O1` | `has_pointee_globals` | 127 |
| `exe-chibicc-O1` | `no_pointee_globals` | 1 |
| `exe-curl-O1` | `has_pointee_globals` | 55 |
| `exe-curl-O1` | `no_pointee_globals` | 1 |
| `exe-gifsicle-O1` | `has_pointee_globals` | 151 |
| `exe-jpegoptim-O1` | `has_pointee_globals` | 18 |
| `exe-jq-O1` | `has_pointee_globals` | 357 |
| `exe-jq-O1` | `no_pointee_globals` | 39 |
| `exe-lua-O1` | `has_pointee_globals` | 306 |
| `exe-tmux-O1` | `has_pointee_globals` | 435 |
| `lib-parson-O1` | `has_pointee_globals` | 97 |

## Top Steens External Mod Nodes

### exe-chibicc-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `tokenize` | `tokenize@!noloc#107` | `val:tokenize:%tokenize::tmp1` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `struct_members` | `struct_members@!noloc#39` | `val:struct_members:%struct_members::tmp0` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `read_macro_arg_one` | `read_macro_arg_one@!noloc#13` | `val:read_macro_arg_one:%read_macro_arg_one::tmp0` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#525` | `val:preprocess2:%preprocess2::tmp8` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#524` | `val:preprocess2:%preprocess2::tmp7` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#523` | `val:preprocess2:%preprocess2::tmp6` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#522` | `val:preprocess2:%preprocess2::tmp4` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#521` | `val:preprocess2:%preprocess2::tmp2` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#520` | `val:preprocess2:%preprocess2::tmp0` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#376` | `val:postfix:%postfix::tmp180` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#375` | `val:postfix:%postfix::tmp29` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#374` | `val:postfix:%postfix::tmp17` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `parse` | `parse@!noloc#57` | `val:parse:%parse::tmp11` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `hashmap_put2` | `hashmap_put2@!noloc#27` | `val:hashmap_put2:%hashmap_put2::tmp5` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `global_variable` | `global_variable@!noloc#46` | `val:global_variable:%global_variable::tmp0` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `func_params` | `func_params@!noloc#27` | `val:func_params:%func_params::tmp5` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `eval_const_expr` | `eval_const_expr@!noloc#50` | `val:eval_const_expr:%eval_const_expr::tmp11` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declarator` | `declarator@!noloc#19` | `val:declarator:%declarator::tmp2` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declaration` | `declaration@!noloc#149` | `val:declaration:%declaration::tmp2` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declaration` | `declaration@!noloc#148` | `val:declaration:%declaration::tmp1` | `136 globals: .compoundliteral+.compoundliteral.1+.compoundliteral.10+.compoundliteral.11+...` | 1 |

### exe-curl-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#20` | `val:main:%main::tmp0` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `getparameter` | `getparameter@!noloc#408` | `val:getparameter:%getparameter::nextarg.addr.6` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `create_transfer` | `create_transfer@!noloc#285` | `val:create_transfer:%create_transfer::tmp2` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `config_init` | `config_init@!noloc#10` | `val:config_init:%config_init::tmp0` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `tool_ssls_load` | `tool_ssls_load@!noloc#7` | `val:tool_ssls_load:%tool_ssls_load::call8` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#42` | `val:tool_header_cb:%tool_header_cb::call34.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#41` | `val:tool_header_cb:%tool_header_cb::call30.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#38` | `val:tool_header_cb:%tool_header_cb::call8.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `proto2num` | `proto2num@!noloc#12` | `val:proto2num:%proto2num::tmp2` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#8` | `val:parseconfig:%parseconfig::line.0` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#16` | `val:parseconfig:%parseconfig::line.3` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#12` | `val:parseconfig:%parseconfig::param.addr.0.i.ph` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `new_getout` | `new_getout@!noloc#3` | `val:new_getout:%new_getout::.sink` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `ipfs_url_rewrite` | `ipfs_url_rewrite@!noloc#35` | `val:ipfs_url_rewrite:%ipfs_url_rewrite::tmp26` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#49` | `val:glob_url:%glob_url::buf.0.ph197.i.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#27` | `val:glob_url:%glob_url::tmp20` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#16` | `val:glob_url:%glob_url::buf.2.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#15` | `val:glob_url:%glob_url::buf.0.i` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#1` | `val:glob_url:%glob_url::call1` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |
| `edge:store|omega:steens_external` | `glob_next_url` | `glob_next_url@!noloc#31` | `val:glob_next_url:%glob_next_url::incdec.ptr` | `332 globals: .str.1.757+.str.100.452+.str.101.453+.str.102.454+...` | 1 |

### exe-gifsicle-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `resize_stream` | `resize_stream@!noloc#231` | `val:resize_stream:%resize_stream::call6.i.i` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `resize_stream` | `resize_stream@!noloc#229` | `val:resize_stream:%resize_stream::tmp20` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1169` | `val:optimize_fragments:%optimize_fragments::begin_same.1206.i.i` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1167` | `val:optimize_fragments:%optimize_fragments::tmp632` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1166` | `val:optimize_fragments:%optimize_fragments::tmp631` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1165` | `val:optimize_fragments:%optimize_fragments::call.i696` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1161` | `val:optimize_fragments:%optimize_fragments::call.i284.i535` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1159` | `val:optimize_fragments:%optimize_fragments::tmp393` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1158` | `val:optimize_fragments:%optimize_fragments::tmp392` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1155` | `val:optimize_fragments:%optimize_fragments::begin_same.1204.i.i` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1153` | `val:optimize_fragments:%optimize_fragments::tmp288` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1152` | `val:optimize_fragments:%optimize_fragments::tmp287` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1151` | `val:optimize_fragments:%optimize_fragments::call.i35` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1147` | `val:optimize_fragments:%optimize_fragments::call.i284.i` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1145` | `val:optimize_fragments:%optimize_fragments::tmp47` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1144` | `val:optimize_fragments:%optimize_fragments::tmp46` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#1256` | `val:main:%main::call.i1272` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#1255` | `val:main:%main::call.i` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `finish_string_list` | `finish_string_list@!noloc#16` | `val:finish_string_list:%finish_string_list::call1` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `colormap_image_floyd_steinberg` | `colormap_image_floyd_steinberg@!noloc#66` | `val:colormap_image_floyd_steinberg:%colormap_image_floyd_steinberg::err1.0427453` | `60 globals: .str.135+.str.21+Clp_SetOptions.opt_generation+active_next_output+...` | 1 |

### exe-jpegoptim-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `jpeg_custom_src` | `jpeg_custom_src@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:183:27#0` | `val:jpeg_custom_src:%jpeg_custom_src::tmp10` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:649:9#0` | `val:optimize:%optimize::inbufferused` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:647:17#0` | `val:optimize:%optimize::inbuffer` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1127:11#0` | `val:optimize:%optimize::saved` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1122:9#0` | `val:optimize:%optimize::rate` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1064:19#0` | `val:optimize:%optimize::outbuffersize` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1049:15#0` | `val:optimize:%optimize::outbuffer` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@!noloc#23` | `val:optimize:%optimize::inbuffersize` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_term_destination` | `jpeg_memory_term_destination@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:95:21#0` | `val:jpeg_memory_term_destination:%jpeg_memory_term_destination::tmp6` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_term_destination` | `jpeg_memory_term_destination@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:94:17#0` | `val:jpeg_memory_term_destination:%jpeg_memory_term_destination::tmp3` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_empty_output_buffer` | `jpeg_memory_empty_output_buffer@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:80:17#0` | `val:jpeg_memory_empty_output_buffer:%jpeg_memory_empty_output_buffer::tmp16` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_term_source` | `custom_term_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:154:21#0` | `val:custom_term_source:%custom_term_source::tmp2` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_init_source` | `custom_init_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:67:21#0` | `val:custom_init_source:%custom_init_source::tmp2` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_mem_input_buffer` | `custom_fill_mem_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:122:23#0` | `val:custom_fill_mem_input_buffer:%custom_fill_mem_input_buffer::tmp5` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:99:18#0` | `val:custom_fill_input_buffer:%custom_fill_input_buffer::tmp22` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:89:24#0` | `val:custom_fill_input_buffer:%custom_fill_input_buffer::tmp11` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:105:22#0` | `val:custom_fill_input_buffer:%custom_fill_input_buffer::tmp28` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |
| `edge:memcpy_dst|omega:steens_external` | `splitdir` | `splitdir@/home/brk/pangs-corpus/jpegoptim/misc.c:266:3#0` | `val:splitdir:%splitdir::buf` | `77 globals: .str+.str.1+.str.10+.str.11+...` | 1 |

### exe-jq-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `parser_init` | `parser_init@!noloc#22` | `val:parser_init:%parser_init::tmp11` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jvp_dtoa_context_init` | `jvp_dtoa_context_init@!noloc#1` | `val:jvp_dtoa_context_init:%jvp_dtoa_context_init::C6` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_yylex_init_extra` | `jq_yylex_init_extra@!noloc#8` | `val:jq_yylex_init_extra:%jq_yylex_init_extra::call.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_yylex_init` | `jq_yylex_init@!noloc#7` | `val:jq_yylex_init:%jq_yylex_init::call.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_util_input_read_more` | `jq_util_input_read_more@!noloc#57` | `val:jq_util_input_read_more:%jq_util_input_read_more::arrayidx` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_init` | `jq_init@!noloc#23` | `val:jq_init:%jq_init::call` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_var_binding` | `gen_var_binding@!noloc#9` | `val:gen_var_binding:%gen_var_binding::call.i.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#69` | `val:gen_try:%gen_try::call.i.i100` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#66` | `val:gen_try:%gen_try::call.i.i66` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#63` | `val:gen_try:%gen_try::call.i.i47` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#60` | `val:gen_try:%gen_try::call.i.i33` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#57` | `val:gen_try:%gen_try::call.i.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#51` | `val:gen_subexp:%gen_subexp::call.i.i64` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#48` | `val:gen_subexp:%gen_subexp::call.i.i48` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#45` | `val:gen_subexp:%gen_subexp::call.i.i33` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#42` | `val:gen_subexp:%gen_subexp::call.i.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#80` | `val:gen_reduce:%gen_reduce::call.i.i182` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#77` | `val:gen_reduce:%gen_reduce::call.i.i134` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#74` | `val:gen_reduce:%gen_reduce::call.i.i101` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#71` | `val:gen_reduce:%gen_reduce::call.i.i` | `120 globals: .str.1.477+.str.100.1141+.str.101.1142+.str.102.1143+...` | 1 |

### exe-lua-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#24` | `val:prepbuffsize:%prepbuffsize::call.i49` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `luaZ_init` | `luaZ_init@!noloc#3` | `val:luaZ_init:%luaZ_init::tmp0` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `luaS_init` | `luaS_init@!noloc#6` | `val:luaS_init:%luaS_init::call` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `warnf` | `warnf@!noloc#13` | `val:warnf:%warnf::tmp0` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `trynewtbcupval` | `trynewtbcupval@!noloc#5` | `val:trynewtbcupval:%trynewtbcupval::tmp4` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `trynewtbcupval` | `trynewtbcupval@!noloc#2` | `val:trynewtbcupval:%trynewtbcupval::next1.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `str_pack` | `str_pack@!noloc#39` | `val:str_pack:%str_pack::len` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `str_gsub` | `str_gsub@!noloc#39` | `val:str_gsub:%str_gsub::l.i.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `str_gsub` | `str_gsub@!noloc#3` | `val:str_gsub:%str_gsub::lp` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `str_find_aux` | `str_find_aux@!noloc#8` | `val:str_find_aux:%str_find_aux::lp` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#65` | `val:singlestep:%singlestep::p.addr.044.i.i109` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#50` | `val:singlestep:%singlestep::p.addr.044.i.i71` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#35` | `val:singlestep:%singlestep::p.addr.044.i.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#22` | `val:singlestep:%singlestep::p.addr.0.i.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `read_long_string` | `read_long_string@!noloc#91` | `val:read_long_string:%read_long_string::b.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `read_long_string` | `read_long_string@!noloc#85` | `val:read_long_string:%read_long_string::tmp55` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `prepclosingmethod` | `prepclosingmethod@!noloc#3` | `val:prepclosingmethod:%prepclosingmethod::tmp3` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#8` | `val:prepbuffsize:%prepbuffsize::box2.i` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#16` | `val:prepbuffsize:%prepbuffsize::box2.i56` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |
| `edge:store|omega:steens_external` | `opencheck` | `opencheck@!noloc#3` | `val:opencheck:%opencheck::f` | `143 globals: .str.1.263+.str.1.805+.str.1.821+.str.10.274+...` | 1 |

### exe-tmux-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `tty_repeat_space` | `tty_repeat_space@/home/brk/pangs-corpus/tmux/tty.c:691:3#0` | `val:tty_repeat_space:i8* getelementptr inbounds ([500 x i8], [500 x i8]* @tty_repeat_space.s, i64 0, i64 0)` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `tty_init` | `tty_init@/home/brk/pangs-corpus/tmux/tty.c:102:2#0` | `val:tty_init:%tty_init::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `screen_write_start` | `screen_write_start@/home/brk/pangs-corpus/tmux/screen-write.c:66:2#0` | `val:screen_write_start:%screen_write_start::tmp1` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `imsg_read` | `imsg_read@/home/brk/pangs-corpus/tmux/compat/imsg.c:61:2#0` | `val:imsg_read:%imsg_read::tmp1` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `freezero` | `freezero@/home/brk/pangs-corpus/tmux/compat/freezero.c:28:3#0` | `val:freezero:%freezero::ptr` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_target` | `cmd_find_target@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_target:%cmd_find_target::tmp2` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_winlink_pane` | `cmd_find_from_winlink_pane@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_winlink_pane:%cmd_find_from_winlink_pane::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_winlink` | `cmd_find_from_winlink@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_winlink:%cmd_find_from_winlink::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_window` | `cmd_find_from_window@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_window:%cmd_find_from_window::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_session_window` | `cmd_find_from_session_window@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_session_window:%cmd_find_from_session_window::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_session` | `cmd_find_from_session@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_session:%cmd_find_from_session::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_nothing` | `cmd_find_from_nothing@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_nothing:%cmd_find_from_nothing::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_mouse` | `cmd_find_from_mouse@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_from_mouse:%cmd_find_from_mouse::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_from_client` | `cmd_find_from_client@!noloc#2` | `val:cmd_find_from_client:%cmd_find_from_client::tmp1` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_client` | `cmd_find_client@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_client:%cmd_find_client::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `stmt:memset_dst|omega:steens_external` | `cmd_find_clear_state` | `cmd_find_clear_state@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | `val:cmd_find_clear_state:%cmd_find_clear_state::tmp0` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `edge:store|omega:steens_external` | `winlink_stack_remove` | `winlink_stack_remove@/home/brk/pangs-corpus/tmux/window.c:265:4#0` | `val:winlink_stack_remove:%winlink_stack_remove::tmp2` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `edge:store|omega:steens_external` | `winlink_stack_push` | `winlink_stack_push@/home/brk/pangs-corpus/tmux/window.c:265:4#0` | `val:winlink_stack_push:%winlink_stack_push::tmp2` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `edge:store|omega:steens_external` | `winlink_stack_push` | `winlink_stack_push@/home/brk/pangs-corpus/tmux/window.c:252:2#0` | `val:winlink_stack_push:%winlink_stack_push::tqh_first` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |
| `edge:store|omega:steens_external` | `winlink_stack_push` | `winlink_stack_push@/home/brk/pangs-corpus/tmux/window.c:252:2#0` | `val:winlink_stack_push:%winlink_stack_push::tqe_next` | `778 globals: .str.1.1259+.str.1.2608+.str.1.3529+.str.10.1268+...` | 1 |

### lib-parson-O1

| detail | func | witness | address node | pointee globals | rows |
|---|---|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `remove_comments` | `remove_comments@!noloc#3` | `val:remove_comments:%remove_comments::string.addr.088` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#84` | `val:parse_value:%parse_value::tmp62` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#81` | `val:parse_value:%parse_value::parent.i119` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#30` | `val:parse_value:%parse_value::tmp13` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#27` | `val:parse_value:%parse_value::parent.i` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#170` | `val:parse_value:%parse_value::parent.i.i80` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#165` | `val:parse_value:%parse_value::parent.i.i69` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#155` | `val:parse_value:%parse_value::call.i63` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#152` | `val:parse_value:%parse_value::parent.i18.i` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#147` | `val:parse_value:%parse_value::parent.i.i57` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#140` | `val:parse_value:%parse_value::parent.i.i` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_string_with_len` | `json_value_init_string_with_len@!noloc#14` | `val:json_value_init_string_with_len:%json_value_init_string_with_len::parent.i` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_object` | `json_value_init_object@!noloc#7` | `val:json_value_init_object:%json_value_init_object::tmp5` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_object` | `json_value_init_object@!noloc#4` | `val:json_value_init_object:%json_value_init_object::parent` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_number` | `json_value_init_number@!noloc#2` | `val:json_value_init_number:%json_value_init_number::parent` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_null` | `json_value_init_null@!noloc#2` | `val:json_value_init_null:%json_value_init_null::parent` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_boolean` | `json_value_init_boolean@!noloc#2` | `val:json_value_init_boolean:%json_value_init_boolean::parent` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_array` | `json_value_init_array@!noloc#7` | `val:json_value_init_array:%json_value_init_array::tmp5` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_array` | `json_value_init_array@!noloc#4` | `val:json_value_init_array:%json_value_init_array::parent` | `parson_float_format` | 1 |
| `edge:store|omega:steens_external` | `json_value_deep_copy` | `json_value_deep_copy@!noloc#93` | `val:json_value_deep_copy:%json_value_deep_copy::parent.i258` | `parson_float_format` | 1 |


## Top Unknown Mod Sites

### exe-chibicc-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `tokenize` | `tokenize@!noloc#107` | 1 |
| `stmt:memset_dst|omega:steens_external` | `struct_members` | `struct_members@!noloc#39` | 1 |
| `stmt:memset_dst|omega:steens_external` | `read_macro_arg_one` | `read_macro_arg_one@!noloc#13` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#525` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#524` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#523` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#522` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#521` | 1 |
| `stmt:memset_dst|omega:steens_external` | `preprocess2` | `preprocess2@!noloc#520` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#376` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#375` | 1 |
| `stmt:memset_dst|omega:steens_external` | `postfix` | `postfix@!noloc#374` | 1 |
| `stmt:memset_dst|omega:steens_external` | `parse` | `parse@!noloc#57` | 1 |
| `stmt:memset_dst|omega:steens_external` | `hashmap_put2` | `hashmap_put2@!noloc#27` | 1 |
| `stmt:memset_dst|omega:steens_external` | `global_variable` | `global_variable@!noloc#46` | 1 |
| `stmt:memset_dst|omega:steens_external` | `func_params` | `func_params@!noloc#27` | 1 |
| `stmt:memset_dst|omega:steens_external` | `eval_const_expr` | `eval_const_expr@!noloc#50` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declarator` | `declarator@!noloc#19` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declaration` | `declaration@!noloc#149` | 1 |
| `stmt:memset_dst|omega:steens_external` | `declaration` | `declaration@!noloc#148` | 1 |

### exe-curl-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#20` | 1 |
| `stmt:memset_dst|omega:steens_external` | `getparameter` | `getparameter@!noloc#408` | 1 |
| `stmt:memset_dst|omega:steens_external` | `create_transfer` | `create_transfer@!noloc#285` | 1 |
| `stmt:memset_dst|omega:steens_external` | `config_init` | `config_init@!noloc#10` | 1 |
| `edge:store|omega:unknown` | `tool_readbusy_cb` | `tool_readbusy_cb@!noloc#25` | 1 |
| `edge:store|omega:unknown` | `tool_mime_stdin_seek` | `tool_mime_stdin_seek@!noloc#5` | 1 |
| `edge:store|omega:steens_external` | `tool_ssls_load` | `tool_ssls_load@!noloc#7` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#42` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#41` | 1 |
| `edge:store|omega:steens_external` | `tool_header_cb` | `tool_header_cb@!noloc#38` | 1 |
| `edge:store|omega:steens_external` | `proto2num` | `proto2num@!noloc#12` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#8` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#16` | 1 |
| `edge:store|omega:steens_external` | `parseconfig` | `parseconfig@!noloc#12` | 1 |
| `edge:store|omega:steens_external` | `new_getout` | `new_getout@!noloc#3` | 1 |
| `edge:store|omega:steens_external` | `ipfs_url_rewrite` | `ipfs_url_rewrite@!noloc#35` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#49` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#27` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#16` | 1 |
| `edge:store|omega:steens_external` | `glob_url` | `glob_url@!noloc#15` | 1 |

### exe-gifsicle-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:unknown` | `Clp_NewParserState` | `Clp_NewParserState@!noloc#5` | 1 |
| `stmt:memset_dst|omega:steens_external` | `resize_stream` | `resize_stream@!noloc#231` | 1 |
| `stmt:memset_dst|omega:steens_external` | `resize_stream` | `resize_stream@!noloc#229` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1169` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1167` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1166` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1165` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1161` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1159` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1158` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1155` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1153` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1152` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1151` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1147` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1145` | 1 |
| `stmt:memset_dst|omega:steens_external` | `optimize_fragments` | `optimize_fragments@!noloc#1144` | 1 |
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#1256` | 1 |
| `stmt:memset_dst|omega:steens_external` | `main` | `main@!noloc#1255` | 1 |
| `stmt:memset_dst|omega:steens_external` | `finish_string_list` | `finish_string_list@!noloc#16` | 1 |

### exe-jpegoptim-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `jpeg_custom_src` | `jpeg_custom_src@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:183:27#0` | 1 |
| `edge:store|omega:unknown` | `parse_markers` | `parse_markers@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:614:17#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:649:9#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:647:17#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1127:11#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1122:9#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1064:19#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:1049:15#0` | 1 |
| `edge:store|omega:steens_external` | `optimize` | `optimize@!noloc#23` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_term_destination` | `jpeg_memory_term_destination@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:95:21#0` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_term_destination` | `jpeg_memory_term_destination@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:94:17#0` | 1 |
| `edge:store|omega:steens_external` | `jpeg_memory_empty_output_buffer` | `jpeg_memory_empty_output_buffer@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:80:17#0` | 1 |
| `edge:store|omega:steens_external` | `custom_term_source` | `custom_term_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:154:21#0` | 1 |
| `edge:store|omega:steens_external` | `custom_init_source` | `custom_init_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:67:21#0` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_mem_input_buffer` | `custom_fill_mem_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:122:23#0` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:99:18#0` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:89:24#0` | 1 |
| `edge:store|omega:steens_external` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:105:22#0` | 1 |
| `edge:memcpy_dst|omega:steens_external` | `splitdir` | `splitdir@/home/brk/pangs-corpus/jpegoptim/misc.c:266:3#0` | 1 |

### exe-jq-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `parser_init` | `parser_init@!noloc#22` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jvp_dtoa_context_init` | `jvp_dtoa_context_init@!noloc#1` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_yylex_init_extra` | `jq_yylex_init_extra@!noloc#8` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_yylex_init` | `jq_yylex_init@!noloc#7` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_util_input_read_more` | `jq_util_input_read_more@!noloc#57` | 1 |
| `stmt:memset_dst|omega:steens_external` | `jq_init` | `jq_init@!noloc#23` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_var_binding` | `gen_var_binding@!noloc#9` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#69` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#66` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#63` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#60` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_try` | `gen_try@!noloc#57` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#51` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#48` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#45` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_subexp` | `gen_subexp@!noloc#42` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#80` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#77` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#74` | 1 |
| `stmt:memset_dst|omega:steens_external` | `gen_reduce` | `gen_reduce@!noloc#71` | 1 |

### exe-lua-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#24` | 1 |
| `stmt:memset_dst|omega:steens_external` | `luaZ_init` | `luaZ_init@!noloc#3` | 1 |
| `stmt:memset_dst|omega:steens_external` | `luaS_init` | `luaS_init@!noloc#6` | 1 |
| `edge:store|omega:steens_external` | `warnf` | `warnf@!noloc#13` | 1 |
| `edge:store|omega:steens_external` | `trynewtbcupval` | `trynewtbcupval@!noloc#5` | 1 |
| `edge:store|omega:steens_external` | `trynewtbcupval` | `trynewtbcupval@!noloc#2` | 1 |
| `edge:store|omega:steens_external` | `str_pack` | `str_pack@!noloc#39` | 1 |
| `edge:store|omega:steens_external` | `str_gsub` | `str_gsub@!noloc#39` | 1 |
| `edge:store|omega:steens_external` | `str_gsub` | `str_gsub@!noloc#3` | 1 |
| `edge:store|omega:steens_external` | `str_find_aux` | `str_find_aux@!noloc#8` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#65` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#50` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#35` | 1 |
| `edge:store|omega:steens_external` | `singlestep` | `singlestep@!noloc#22` | 1 |
| `edge:store|omega:steens_external` | `read_long_string` | `read_long_string@!noloc#91` | 1 |
| `edge:store|omega:steens_external` | `read_long_string` | `read_long_string@!noloc#85` | 1 |
| `edge:store|omega:steens_external` | `prepclosingmethod` | `prepclosingmethod@!noloc#3` | 1 |
| `edge:store|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#8` | 1 |
| `edge:store|omega:steens_external` | `prepbuffsize` | `prepbuffsize@!noloc#16` | 1 |
| `edge:store|omega:steens_external` | `opencheck` | `opencheck@!noloc#3` | 1 |

### exe-tmux-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `edge:store|omega:steens_external` | `screen_write_box` | `screen_write_box@/home/brk/pangs-corpus/tmux/screen-write.c:125:2#0` | 8 |
| `edge:store|omega:steens_external` | `layout_split_pane` | `layout_split_pane@/home/brk/pangs-corpus/tmux/layout.c:60:2#0` | 4 |
| `edge:store|omega:steens_external` | `layout_split_pane` | `layout_split_pane@/home/brk/pangs-corpus/tmux/layout.c:57:11#0` | 4 |
| `edge:store|omega:steens_external` | `screen_write_vline` | `screen_write_vline@/home/brk/pangs-corpus/tmux/screen-write.c:125:2#0` | 3 |
| `edge:store|omega:steens_external` | `screen_write_hline` | `screen_write_hline@/home/brk/pangs-corpus/tmux/screen-write.c:125:2#0` | 3 |
| `edge:store|omega:steens_external` | `winlink_stack_push` | `winlink_stack_push@/home/brk/pangs-corpus/tmux/window.c:252:2#0` | 2 |
| `edge:store|omega:steens_external` | `winlink_set_window` | `winlink_set_window@/home/brk/pangs-corpus/tmux/window.c:191:2#0` | 2 |
| `edge:store|omega:steens_external` | `window_add_pane` | `window_add_pane@/home/brk/pangs-corpus/tmux/window.c:633:4#0` | 2 |
| `edge:store|omega:steens_external` | `window_add_pane` | `window_add_pane@/home/brk/pangs-corpus/tmux/window.c:631:4#0` | 2 |
| `edge:store|omega:steens_external` | `window_add_pane` | `window_add_pane@/home/brk/pangs-corpus/tmux/window.c:627:4#0` | 2 |
| `edge:store|omega:steens_external` | `window_add_pane` | `window_add_pane@/home/brk/pangs-corpus/tmux/window.c:625:4#0` | 2 |
| `edge:store|omega:steens_external` | `window_add_pane` | `window_add_pane@/home/brk/pangs-corpus/tmux/window.c:621:3#0` | 2 |
| `edge:store|omega:steens_external` | `session_renumber_windows` | `session_renumber_windows@/home/brk/pangs-corpus/tmux/session.c:766:4#0` | 2 |
| `edge:store|omega:steens_external` | `session_group_synchronize1` | `session_group_synchronize1@/home/brk/pangs-corpus/tmux/session.c:717:4#0` | 2 |
| `edge:store|omega:steens_external` | `session_group_add` | `session_group_add@/home/brk/pangs-corpus/tmux/session.c:603:3#0` | 2 |
| `edge:store|omega:steens_external` | `server_client_add_message` | `server_client_add_message@/home/brk/pangs-corpus/tmux/variadic.c:628:2#0` | 2 |
| `edge:store|omega:steens_external` | `screen_write_collect_scroll` | `screen_write_collect_scroll@/home/brk/pangs-corpus/tmux/screen-write.c:1220:3#0` | 2 |
| `edge:store|omega:steens_external` | `screen_write_collect_end` | `screen_write_collect_end@/home/brk/pangs-corpus/tmux/screen-write.c:1290:2#0` | 2 |
| `edge:store|omega:steens_external` | `screen_push_title` | `screen_push_title@/home/brk/pangs-corpus/tmux/screen.c:156:2#0` | 2 |
| `edge:store|omega:steens_external` | `mode_tree_build` | `mode_tree_build@/home/brk/pangs-corpus/tmux/mode-tree.c:371:2#0` | 2 |

### lib-parson-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst|omega:steens_external` | `remove_comments` | `remove_comments@!noloc#3` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#84` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#81` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#30` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#27` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#170` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#165` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#155` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#152` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#147` | 1 |
| `edge:store|omega:steens_external` | `parse_value` | `parse_value@!noloc#140` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_string_with_len` | `json_value_init_string_with_len@!noloc#14` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_object` | `json_value_init_object@!noloc#7` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_object` | `json_value_init_object@!noloc#4` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_number` | `json_value_init_number@!noloc#2` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_null` | `json_value_init_null@!noloc#2` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_boolean` | `json_value_init_boolean@!noloc#2` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_array` | `json_value_init_array@!noloc#7` | 1 |
| `edge:store|omega:steens_external` | `json_value_init_array` | `json_value_init_array@!noloc#4` | 1 |
| `edge:store|omega:steens_external` | `json_value_deep_copy` | `json_value_deep_copy@!noloc#93` | 1 |


## Frozen-Component Taints

### exe-chibicc-O1

- `unknown_global`: 212
- `fnptr_varargs_internal_unmodeled`: 91
- `fnptr_ptrtoint`: 14
- `fnptr_varargs_external`: 9
- `unknown_caller`: 2
- `unknown_callee`: 1
- `memset_fnptr_aggregate`: 1
- `fnptr_inttoptr`: 1

### exe-curl-O1

- `unknown_global`: 272
- `fnptr_varargs_internal_unmodeled`: 91
- `fnptr_varargs_external`: 35
- `fnptr_ptrtoint`: 14
- `unknown_caller`: 1
- `unknown_callee`: 1
- `inline_asm`: 1

### exe-gifsicle-O1

- `unknown_global`: 371
- `unknown_callee`: 203
- `fnptr_varargs_internal_unmodeled`: 30
- `fnptr_varargs_external`: 22
- `fnptr_ptrtoint`: 19
- `unknown_caller`: 9
- `memcpy_fnptr_aggregate`: 2
- `fnptr_varargs_indirect`: 2
- `memset_fnptr_aggregate`: 1

### exe-jpegoptim-O1

- `unknown_global`: 36
- `fnptr_varargs_internal_unmodeled`: 29
- `fnptr_varargs_external`: 24
- `unknown_callee`: 14
- `unknown_caller`: 1
- `setjmp_longjmp`: 1
- `fnptr_ptrtoint`: 1

### exe-jq-O1

- `unknown_global`: 879
- `fnptr_varargs_internal_unmodeled`: 95
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 20
- `unknown_callee`: 8
- `unknown_caller`: 1

### exe-lua-O1

- `unknown_global`: 1151
- `fnptr_varargs_internal_unmodeled`: 87
- `unknown_callee`: 64
- `fnptr_ptrtoint`: 48
- `fnptr_varargs_external`: 22
- `fnptr_inttoptr`: 2
- `unknown_caller`: 1

### exe-tmux-O1

- `unknown_global`: 1094
- `fnptr_varargs_internal_unmodeled`: 70
- `unknown_callee`: 49
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 31
- `memset_fnptr_aggregate`: 4
- `unknown_caller`: 1

### lib-parson-O1

- `unknown_global`: 129
- `fnptr_ptrtoint`: 6
- `unknown_caller`: 1

## Initval Diagnostics

### exe-chibicc-O1

- `no_modeled_pointer_initializer`: 133

### exe-curl-O1

- `no_modeled_pointer_initializer`: 80

### exe-gifsicle-O1

- `no_modeled_pointer_initializer`: 93

### exe-jpegoptim-O1

- `no_modeled_pointer_initializer`: 48

### exe-jq-O1

- `no_modeled_pointer_initializer`: 14

### exe-lua-O1

- `no_modeled_pointer_initializer`: 5

### exe-tmux-O1

- `no_modeled_pointer_initializer`: 107

### lib-parson-O1

- `no_modeled_pointer_initializer`: 5

## Top Runtime Writers

### exe-chibicc-O1

- none

### exe-curl-O1

- none

### exe-gifsicle-O1

- none

### exe-jpegoptim-O1

- none

### exe-jq-O1

- none

### exe-lua-O1

- none

### exe-tmux-O1

- none

### lib-parson-O1

- none

