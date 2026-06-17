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
| `exe-chibicc-O1` | 49 | 81 | 133 | 52 |
| `exe-curl-O1` | 35 | 51 | 80 | 29 |
| `exe-gifsicle-O1` | 77 | 90 | 93 | 3 |
| `exe-jpegoptim-O1` | 10 | 46 | 48 | 2 |
| `exe-jq-O1` | 137 | 8 | 14 | 6 |
| `exe-lua-O1` | 127 | 5 | 5 | 0 |
| `exe-tmux-O1` | 252 | 79 | 107 | 28 |
| `lib-parson-O1` | 43 | 5 | 5 | 0 |

## Unknown Mod Sources

| row | detail | rows |
|---|---|---:|
| `exe-chibicc-O1` | `edge:store` | 21 |
| `exe-chibicc-O1` | `stmt:memset_dst` | 14 |
| `exe-chibicc-O1` | `edge:memcpy_dst` | 14 |
| `exe-curl-O1` | `edge:store` | 20 |
| `exe-curl-O1` | `edge:memcpy_dst` | 11 |
| `exe-curl-O1` | `stmt:memset_dst` | 4 |
| `exe-gifsicle-O1` | `edge:store` | 41 |
| `exe-gifsicle-O1` | `edge:memcpy_dst` | 21 |
| `exe-gifsicle-O1` | `stmt:memset_dst` | 15 |
| `exe-jpegoptim-O1` | `edge:store` | 8 |
| `exe-jpegoptim-O1` | `stmt:memset_dst` | 1 |
| `exe-jpegoptim-O1` | `edge:memcpy_dst` | 1 |
| `exe-jq-O1` | `edge:store` | 89 |
| `exe-jq-O1` | `stmt:memset_dst` | 46 |
| `exe-jq-O1` | `edge:memcpy_dst` | 2 |
| `exe-lua-O1` | `edge:store` | 116 |
| `exe-lua-O1` | `edge:memcpy_dst` | 8 |
| `exe-lua-O1` | `stmt:memset_dst` | 3 |
| `exe-tmux-O1` | `edge:store` | 208 |
| `exe-tmux-O1` | `edge:memcpy_dst` | 28 |
| `exe-tmux-O1` | `stmt:memset_dst` | 16 |
| `lib-parson-O1` | `edge:store` | 24 |
| `lib-parson-O1` | `edge:memcpy_dst` | 18 |
| `lib-parson-O1` | `stmt:memset_dst` | 1 |

## Top Unknown Mod Sites

### exe-chibicc-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `tokenize` | `tokenize@!noloc#107` | 1 |
| `stmt:memset_dst` | `struct_members` | `struct_members@!noloc#39` | 1 |
| `stmt:memset_dst` | `read_macro_arg_one` | `read_macro_arg_one@!noloc#13` | 1 |
| `stmt:memset_dst` | `preprocess2` | `preprocess2@!noloc#520` | 1 |
| `stmt:memset_dst` | `postfix` | `postfix@!noloc#374` | 1 |
| `stmt:memset_dst` | `parse` | `parse@!noloc#57` | 1 |
| `stmt:memset_dst` | `hashmap_put2` | `hashmap_put2@!noloc#27` | 1 |
| `stmt:memset_dst` | `global_variable` | `global_variable@!noloc#46` | 1 |
| `stmt:memset_dst` | `func_params` | `func_params@!noloc#27` | 1 |
| `stmt:memset_dst` | `eval_const_expr` | `eval_const_expr@!noloc#50` | 1 |
| `stmt:memset_dst` | `declarator` | `declarator@!noloc#19` | 1 |
| `stmt:memset_dst` | `declaration` | `declaration@!noloc#147` | 1 |
| `stmt:memset_dst` | `compound_stmt` | `compound_stmt@!noloc#37` | 1 |
| `stmt:memset_dst` | `abstract_declarator` | `abstract_declarator@!noloc#13` | 1 |
| `edge:store` | `write_gvar_data` | `write_gvar_data@!noloc#43` | 1 |
| `edge:store` | `tokenize_file` | `tokenize_file@!noloc#25` | 1 |
| `edge:store` | `to_assign` | `to_assign@!noloc#102` | 1 |
| `edge:store` | `struct_members` | `struct_members@!noloc#25` | 1 |
| `edge:store` | `preprocess2` | `preprocess2@!noloc#102` | 1 |
| `edge:store` | `postfix` | `postfix@!noloc#337` | 1 |

### exe-curl-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `main` | `main@!noloc#20` | 1 |
| `stmt:memset_dst` | `getparameter` | `getparameter@!noloc#408` | 1 |
| `stmt:memset_dst` | `create_transfer` | `create_transfer@!noloc#285` | 1 |
| `stmt:memset_dst` | `config_init` | `config_init@!noloc#10` | 1 |
| `edge:store` | `tool_ssls_load` | `tool_ssls_load@!noloc#7` | 1 |
| `edge:store` | `tool_readbusy_cb` | `tool_readbusy_cb@!noloc#25` | 1 |
| `edge:store` | `tool_read_cb` | `tool_read_cb@!noloc#14` | 1 |
| `edge:store` | `tool_mime_stdin_seek` | `tool_mime_stdin_seek@!noloc#5` | 1 |
| `edge:store` | `tool_header_cb` | `tool_header_cb@!noloc#38` | 1 |
| `edge:store` | `proto2num` | `proto2num@!noloc#12` | 1 |
| `edge:store` | `parseconfig` | `parseconfig@!noloc#12` | 1 |
| `edge:store` | `new_getout` | `new_getout@!noloc#3` | 1 |
| `edge:store` | `ipfs_url_rewrite` | `ipfs_url_rewrite@!noloc#35` | 1 |
| `edge:store` | `glob_url` | `glob_url@!noloc#1` | 1 |
| `edge:store` | `glob_next_url` | `glob_next_url@!noloc#30` | 1 |
| `edge:store` | `glob_match_url` | `glob_match_url@!noloc#17` | 1 |
| `edge:store` | `get_url_file_name` | `get_url_file_name@!noloc#4` | 1 |
| `edge:store` | `get_param_word` | `get_param_word@!noloc#8` | 1 |
| `edge:store` | `get_param_part` | `get_param_part@!noloc#101` | 1 |
| `edge:store` | `formparse` | `formparse@!noloc#1` | 1 |

### exe-gifsicle-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `resize_stream` | `resize_stream@!noloc#229` | 1 |
| `stmt:memset_dst` | `optimize_fragments` | `optimize_fragments@!noloc#1144` | 1 |
| `stmt:memset_dst` | `main` | `main@!noloc#1255` | 1 |
| `stmt:memset_dst` | `finish_string_list` | `finish_string_list@!noloc#16` | 1 |
| `stmt:memset_dst` | `colormap_image_floyd_steinberg` | `colormap_image_floyd_steinberg@!noloc#66` | 1 |
| `stmt:memset_dst` | `Gif_SetUncompressedImage` | `Gif_SetUncompressedImage@!noloc#12` | 1 |
| `stmt:memset_dst` | `Gif_ReleaseUncompressedImage` | `Gif_ReleaseUncompressedImage@!noloc#4` | 1 |
| `stmt:memset_dst` | `Gif_NewStream` | `Gif_NewStream@!noloc#4` | 1 |
| `stmt:memset_dst` | `Gif_NewImage` | `Gif_NewImage@!noloc#4` | 1 |
| `stmt:memset_dst` | `Gif_NewComment` | `Gif_NewComment@!noloc#0` | 1 |
| `stmt:memset_dst` | `Gif_MakeImageEmpty` | `Gif_MakeImageEmpty@!noloc#27` | 1 |
| `stmt:memset_dst` | `Gif_CopyStreamSkeleton` | `Gif_CopyStreamSkeleton@!noloc#15` | 1 |
| `stmt:memset_dst` | `Gif_CopyStreamImages` | `Gif_CopyStreamImages@!noloc#30` | 1 |
| `stmt:memset_dst` | `Gif_CopyImage` | `Gif_CopyImage@!noloc#79` | 1 |
| `stmt:memset_dst` | `Clp_NewParserState` | `Clp_NewParserState@!noloc#5` | 1 |
| `edge:store` | `uncompress_image` | `uncompress_image@!noloc#36` | 1 |
| `edge:store` | `scale_image_complete` | `scale_image_complete@!noloc#22` | 1 |
| `edge:store` | `rotate_image` | `rotate_image@!noloc#5` | 1 |
| `edge:store` | `resize_stream` | `resize_stream@!noloc#205` | 1 |
| `edge:store` | `read_gif` | `read_gif@!noloc#134` | 1 |

### exe-jpegoptim-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `jpeg_custom_src` | `jpeg_custom_src@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:183:27#0` | 1 |
| `edge:store` | `parse_markers` | `parse_markers@/home/brk/pangs-corpus/jpegoptim/jpegoptim.c:614:17#0` | 1 |
| `edge:store` | `optimize` | `optimize@!noloc#23` | 1 |
| `edge:store` | `jpeg_memory_term_destination` | `jpeg_memory_term_destination@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:94:17#0` | 1 |
| `edge:store` | `jpeg_memory_empty_output_buffer` | `jpeg_memory_empty_output_buffer@/home/brk/pangs-corpus/jpegoptim/jpegdest.c:80:17#0` | 1 |
| `edge:store` | `custom_term_source` | `custom_term_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:154:21#0` | 1 |
| `edge:store` | `custom_init_source` | `custom_init_source@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:67:21#0` | 1 |
| `edge:store` | `custom_fill_mem_input_buffer` | `custom_fill_mem_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:122:23#0` | 1 |
| `edge:store` | `custom_fill_input_buffer` | `custom_fill_input_buffer@/home/brk/pangs-corpus/jpegoptim/jpegsrc.c:105:22#0` | 1 |
| `edge:memcpy_dst` | `splitdir` | `splitdir@/home/brk/pangs-corpus/jpegoptim/misc.c:266:3#0` | 1 |

### exe-jq-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `parser_init` | `parser_init@!noloc#22` | 1 |
| `stmt:memset_dst` | `jvp_dtoa_context_init` | `jvp_dtoa_context_init@!noloc#1` | 1 |
| `stmt:memset_dst` | `jq_yylex_init_extra` | `jq_yylex_init_extra@!noloc#8` | 1 |
| `stmt:memset_dst` | `jq_yylex_init` | `jq_yylex_init@!noloc#7` | 1 |
| `stmt:memset_dst` | `jq_util_input_read_more` | `jq_util_input_read_more@!noloc#57` | 1 |
| `stmt:memset_dst` | `jq_init` | `jq_init@!noloc#23` | 1 |
| `stmt:memset_dst` | `gen_var_binding` | `gen_var_binding@!noloc#9` | 1 |
| `stmt:memset_dst` | `gen_try` | `gen_try@!noloc#57` | 1 |
| `stmt:memset_dst` | `gen_subexp` | `gen_subexp@!noloc#42` | 1 |
| `stmt:memset_dst` | `gen_reduce` | `gen_reduce@!noloc#71` | 1 |
| `stmt:memset_dst` | `gen_param_regular` | `gen_param_regular@!noloc#9` | 1 |
| `stmt:memset_dst` | `gen_param` | `gen_param@!noloc#9` | 1 |
| `stmt:memset_dst` | `gen_or` | `gen_or@!noloc#65` | 1 |
| `stmt:memset_dst` | `gen_op_var_fresh` | `gen_op_var_fresh@!noloc#11` | 1 |
| `stmt:memset_dst` | `gen_op_unbound` | `gen_op_unbound@!noloc#9` | 1 |
| `stmt:memset_dst` | `gen_op_targetlater` | `gen_op_targetlater@!noloc#8` | 1 |
| `stmt:memset_dst` | `gen_op_target` | `gen_op_target@!noloc#8` | 1 |
| `stmt:memset_dst` | `gen_op_simple` | `gen_op_simple@!noloc#7` | 1 |
| `stmt:memset_dst` | `gen_op_pushk_under` | `gen_op_pushk_under@!noloc#9` | 1 |
| `stmt:memset_dst` | `gen_op_bound` | `gen_op_bound@!noloc#12` | 1 |

### exe-lua-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `prepbuffsize` | `prepbuffsize@!noloc#24` | 1 |
| `stmt:memset_dst` | `luaZ_init` | `luaZ_init@!noloc#3` | 1 |
| `stmt:memset_dst` | `luaS_init` | `luaS_init@!noloc#6` | 1 |
| `edge:store` | `warnf` | `warnf@!noloc#13` | 1 |
| `edge:store` | `trynewtbcupval` | `trynewtbcupval@!noloc#2` | 1 |
| `edge:store` | `str_pack` | `str_pack@!noloc#39` | 1 |
| `edge:store` | `str_gsub` | `str_gsub@!noloc#3` | 1 |
| `edge:store` | `str_format` | `str_format@!noloc#90` | 1 |
| `edge:store` | `str_find_aux` | `str_find_aux@!noloc#8` | 1 |
| `edge:store` | `singlestep` | `singlestep@!noloc#22` | 1 |
| `edge:store` | `read_long_string` | `read_long_string@!noloc#85` | 1 |
| `edge:store` | `prepclosingmethod` | `prepclosingmethod@!noloc#3` | 1 |
| `edge:store` | `prepbuffsize` | `prepbuffsize@!noloc#16` | 1 |
| `edge:store` | `opencheck` | `opencheck@!noloc#1` | 1 |
| `edge:store` | `new_localvar` | `new_localvar@!noloc#23` | 1 |
| `edge:store` | `math_randomseed` | `math_randomseed@!noloc#0` | 1 |
| `edge:store` | `math_random` | `math_random@!noloc#12` | 1 |
| `edge:store` | `luaopen_math` | `luaopen_math@!noloc#0` | 1 |
| `edge:store` | `luaopen_io` | `luaopen_io@!noloc#13` | 1 |
| `edge:store` | `lua_xmove` | `lua_xmove@!noloc#5` | 1 |

### exe-tmux-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `tty_repeat_space` | `tty_repeat_space@/home/brk/pangs-corpus/tmux/tty.c:691:3#0` | 1 |
| `stmt:memset_dst` | `tty_init` | `tty_init@/home/brk/pangs-corpus/tmux/tty.c:102:2#0` | 1 |
| `stmt:memset_dst` | `screen_write_start` | `screen_write_start@/home/brk/pangs-corpus/tmux/screen-write.c:66:2#0` | 1 |
| `stmt:memset_dst` | `imsg_read` | `imsg_read@/home/brk/pangs-corpus/tmux/compat/imsg.c:61:2#0` | 1 |
| `stmt:memset_dst` | `freezero` | `freezero@/home/brk/pangs-corpus/tmux/compat/freezero.c:28:3#0` | 1 |
| `stmt:memset_dst` | `cmd_find_target` | `cmd_find_target@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_winlink_pane` | `cmd_find_from_winlink_pane@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_winlink` | `cmd_find_from_winlink@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_window` | `cmd_find_from_window@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_session_window` | `cmd_find_from_session_window@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_session` | `cmd_find_from_session@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_nothing` | `cmd_find_from_nothing@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_mouse` | `cmd_find_from_mouse@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_from_client` | `cmd_find_from_client@!noloc#2` | 1 |
| `stmt:memset_dst` | `cmd_find_client` | `cmd_find_client@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `stmt:memset_dst` | `cmd_find_clear_state` | `cmd_find_clear_state@/home/brk/pangs-corpus/tmux/cmd-find.c:651:2#0` | 1 |
| `edge:store` | `winlink_stack_remove` | `winlink_stack_remove@/home/brk/pangs-corpus/tmux/window.c:265:4#0` | 1 |
| `edge:store` | `winlink_stack_push` | `winlink_stack_push@/home/brk/pangs-corpus/tmux/window.c:252:2#0` | 1 |
| `edge:store` | `winlink_set_window` | `winlink_set_window@/home/brk/pangs-corpus/tmux/window.c:188:3#0` | 1 |
| `edge:store` | `winlink_remove` | `winlink_remove@/home/brk/pangs-corpus/tmux/window.c:202:3#0` | 1 |

### lib-parson-O1

| detail | func | witness | rows |
|---|---|---|---:|
| `stmt:memset_dst` | `remove_comments` | `remove_comments@!noloc#3` | 1 |
| `edge:store` | `parse_value` | `parse_value@!noloc#140` | 1 |
| `edge:store` | `json_value_init_string_with_len` | `json_value_init_string_with_len@!noloc#14` | 1 |
| `edge:store` | `json_value_init_object` | `json_value_init_object@!noloc#4` | 1 |
| `edge:store` | `json_value_init_number` | `json_value_init_number@!noloc#2` | 1 |
| `edge:store` | `json_value_init_null` | `json_value_init_null@!noloc#2` | 1 |
| `edge:store` | `json_value_init_boolean` | `json_value_init_boolean@!noloc#2` | 1 |
| `edge:store` | `json_value_init_array` | `json_value_init_array@!noloc#4` | 1 |
| `edge:store` | `json_value_deep_copy` | `json_value_deep_copy@!noloc#20` | 1 |
| `edge:store` | `json_serialize_to_buffer_r` | `json_serialize_to_buffer_r@!noloc#10` | 1 |
| `edge:store` | `json_serialize_string` | `json_serialize_string@!noloc#1` | 1 |
| `edge:store` | `json_object_set_number` | `json_object_set_number@!noloc#2` | 1 |
| `edge:store` | `json_object_set_null` | `json_object_set_null@!noloc#2` | 1 |
| `edge:store` | `json_object_set_boolean` | `json_object_set_boolean@!noloc#2` | 1 |
| `edge:store` | `json_object_dotset_value` | `json_object_dotset_value@!noloc#12` | 1 |
| `edge:store` | `json_object_dotset_number` | `json_object_dotset_number@!noloc#2` | 1 |
| `edge:store` | `json_object_dotset_null` | `json_object_dotset_null@!noloc#2` | 1 |
| `edge:store` | `json_object_dotset_boolean` | `json_object_dotset_boolean@!noloc#2` | 1 |
| `edge:store` | `json_array_replace_number` | `json_array_replace_number@!noloc#2` | 1 |
| `edge:store` | `json_array_replace_null` | `json_array_replace_null@!noloc#2` | 1 |


## Frozen-Component Taints

### exe-chibicc-O1

- `fnptr_varargs_internal_unmodeled`: 91
- `unknown_global`: 78
- `fnptr_ptrtoint`: 14
- `fnptr_varargs_external`: 9
- `unknown_caller`: 2
- `unknown_callee`: 1
- `memset_fnptr_aggregate`: 1
- `fnptr_inttoptr`: 1

### exe-curl-O1

- `unknown_global`: 106
- `fnptr_varargs_internal_unmodeled`: 91
- `fnptr_varargs_external`: 35
- `fnptr_ptrtoint`: 14
- `unknown_caller`: 1
- `unknown_callee`: 1
- `inline_asm`: 1

### exe-gifsicle-O1

- `unknown_callee`: 203
- `unknown_global`: 153
- `fnptr_varargs_internal_unmodeled`: 30
- `fnptr_varargs_external`: 22
- `fnptr_ptrtoint`: 19
- `unknown_caller`: 9
- `memcpy_fnptr_aggregate`: 2
- `fnptr_varargs_indirect`: 2
- `memset_fnptr_aggregate`: 1

### exe-jpegoptim-O1

- `fnptr_varargs_internal_unmodeled`: 29
- `fnptr_varargs_external`: 24
- `unknown_global`: 18
- `unknown_callee`: 14
- `unknown_caller`: 1
- `setjmp_longjmp`: 1
- `fnptr_ptrtoint`: 1

### exe-jq-O1

- `unknown_global`: 243
- `fnptr_varargs_internal_unmodeled`: 95
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 20
- `unknown_callee`: 8
- `unknown_caller`: 1

### exe-lua-O1

- `unknown_global`: 329
- `fnptr_varargs_internal_unmodeled`: 87
- `unknown_callee`: 64
- `fnptr_ptrtoint`: 48
- `fnptr_varargs_external`: 22
- `fnptr_inttoptr`: 2
- `unknown_caller`: 1

### exe-tmux-O1

- `unknown_global`: 597
- `fnptr_varargs_internal_unmodeled`: 70
- `unknown_callee`: 49
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 31
- `memset_fnptr_aggregate`: 4
- `unknown_caller`: 1

### lib-parson-O1

- `unknown_global`: 49
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

