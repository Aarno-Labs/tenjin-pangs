#!/bin/bash
CC2JSON=~/tenjin/_local/xj-more-deps/bin/cc2json-llvm14
INPUTBITCODE=$1
echo LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib $CC2JSON $INPUTBITCODE --datalog-analysis=unification \
                                            --context-sensitivity=insensitive \
                                            --entrypoints=library \
                                            --internalize-globals \
                                            --debug-datalog \
                                            --debug-datalog-dir="_facts" \
                                            --json-out=xj-cclyzer.json
