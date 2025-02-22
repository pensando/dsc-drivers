#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
#

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
IONIC_HAVE_TCP_ALL_HEADERS			symbol		skb_tcp_all_headers		include/linux/tcp.h
IONIC_HAVE_INNER_TCP_ALL_HEADERS		symbol		skb_inner_tcp_all_headers	include/linux/tcp.h
IONIC_HAVE_DEVLINK_DRIVER_NAME_PUT		symbol		devlink_info_driver_name_put	include/net/devlink.h
IONIC_HAVE_DEVLINK_GENERIC_RDMA_ID		symbol		DEVLINK_PARAM_GENERIC_ID_ENABLE_RDMA	include/net/devlink.h
IONIC_HAVE_SET_NETDEV_DEVLINK_PORT		symbol		SET_NETDEV_DEVLINK_PORT		include/linux/netdevice.h
IONIC_HAVE_DEVLINK_PARAMS_PUBLISH		symtype		devlink_params_publish		include/net/devlink.h		void(struct devlink *)
IONIC_HAVE_DEVLINK_ALLOC_DEV			symtype		devlink_alloc			include/net/devlink.h   struct devlink *(const struct devlink_ops *, size_t, struct device *)
IONIC_HAVE_VOID_DEVLINK_REGISTER		symtype		devlink_register		include/net/devlink.h   void(struct devlink *)
IONIC_HAVE_DEVLINK_REGISTER_WITH_DEV		symtype		devlink_register		include/net/devlink.h   int(struct devlink *, struct device *)
IONIC_HAVE_NET_DIM_SAMPLE_PTR			symtype		net_dim				include/linux/dim.h	void(struct dim *dim, const struct dim_sample *end_sample)
IONIC_HAVE_ETHTOOL_COALESCE_CQE			memtype		struct_ethtool_ops		get_coalesce	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *)
IONIC_HAVE_ETHTOOL_SET_RINGPARAM_EXTACK		memtype		struct_ethtool_ops		set_ringparam	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *)
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
#

err  () { echo >&2 "$*";    }
log  () { err "$me: $*";    }
vlog () { $verbose && err "$me: $*"; }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "'$*' failed"; }
vmsg () { $quiet || log "$@"; }

function usage()
{
    err
    err "usage:"
    err "  $me [options] <symbol1> <symbol2>"
    err
    err "description:"
    err "  Produce a list of kernel compatibility macros to match the "
    err "  kernel_compat.c and kernel_compat.h files"
    err
    err "options:"
    err "  -k KPATH        -- Specify the path to the kernel build source tree"
    err "                     defaults to /lib/modules/VERSION/build"
    err "  -o PATH         -- Specify the output directory, if any"
    err "                     defaults to KPATH"
    err "  -r VERSION      -- Specify the kernel version instead to test"
    err '                     defaults to `uname -r`'
    err "  -a ARCH         -- Set the architecture to ARCH"
    err "                     defaults to `uname -m`"
    err "  -c CROSS_COMPILE-- Set the cross compiler"
    err "                     defaults to none"
    err "  -i include      -- kernel include path LINUXINCLUDE="
    err "                     Use in case including different kernel header files"
    err "  -f OFA ksrc     -- open fabrics kernel source"
    err "                     if specified, OFA_KSRC= given priorify for grep"
    err "                     instead of KBUILD_SRC="
    err "  -m MAP          -- Specify a System map for the build kernel."
    err "                     By default will look in KPATH and /boot"
    err "  -q              -- Quieten the checks"
    err "  -v              -- Verbose output"
    err "  -s              -- Symbol list to use"
    err "  <symbol>        -- Symbol to evaluate."
    err "                     By default every symbol is evaluated"

}

######################################################################
# Generic methods for standard symbol types

# Look for up to 3 numeric components separated by dots and stop when
# we find anything that doesn't match this.  Convert to a number like
# the LINUX_VERSION_CODE macro does.
function string_to_version_code
{
    local ver="$1"
    local code=0
    local place=65536
    local num

    while [ -n "$ver" ]; do
    # Look for numeric component; if none found then we're done;
    # otherwise add to the code
    num=${ver%%[^0-9]*}
    test -n "$num" || break
    code=$((code + $num * $place))

    # If this was the last component (place value = 1) then we're done;
    # otherwise update place value
    test $place -gt 1 || break
    place=$((place / 256))

    # Move past numeric component and following dot (if present)
    ver=${ver#$num}
    ver=${ver#.}
    done

    echo $code
}

# Test cases for string_to_version_code:
# test $(string_to_version_code 1.2.3) = $((1 * 65536 + 2 * 256 + 3))
# test $(string_to_version_code 12.34.56) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.78) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56-foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.0) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-56) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-foo) = $((12 * 65536 + 34 * 256))

function do_kver()
{
    shift 2;
    local op="$1"
    local right_ver="$2"

    local left=$(string_to_version_code "$KVER")
    local right=$(string_to_version_code "$right_ver")

    local result=$((1 - ($left $op $right)))
    local msg="$KVER $op $right_ver == $left $op $right == "
    if [ $result = 0 ]; then
        msg="$msg true"
    else
        msg="$msg false"
    fi
    vmsg "$msg"
    return $result
}

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_symtype() { shift 2; defer_test_symtype pos "$@"; }
function do_nsymtype() { shift 2; defer_test_symtype neg "$@"; }
function do_member() { shift 2; defer_test_member pos "$@"; }
function do_nmember() { shift 2; defer_test_member neg "$@"; }
function do_memtype() { shift 2; defer_test_memtype pos "$@"; }
function do_nmemtype() { shift 2; defer_test_memtype neg "$@"; }
function do_bitfield() { shift 2; defer_test_bitfield pos "$@"; }
function do_nbitfield() { shift 2; defer_test_bitfield neg "$@"; }
function do_export()
{
    local sym=$3
    shift 3

    # Only scan header files for the symbol
    test_symbol $sym $(echo "$@" | sed -r 's/ [^ ]+\.c/ /g') || return
    test_export $sym "$@"
}
function do_nexport() { ! do_export "$@"; }
function do_file()
{
    for file in "$@"; do
        if [ -n "${OFA_KSRC:-}" ]; then
            if [ -f $OFA_KSRC/$file ]; then
                return 0
            fi
            if [ -f $KBUILD_SRC/$file ]; then
               return 0
            fi
        fi
    done
    return 1
}
function do_nfile()   { ! do_file "$@"; }

function do_custom()  { do_$1; }

######################################################################
# Implementation of kernel feature checking

# Special return value for deferred test
DEFERRED=42

function atexit_cleanup()
{
    rc=$?
    [ -n "$rmfiles" ] && rm -rf $rmfiles
    return $rc
}

function strip_comments()
{
    local file=$1

    cat $1 | sed -e '
/\/\*/!b
:a
/\*\//!{
N
ba
}
s:/\*.*\*/::' | sed -e '/^#include/d'
}

function test_symbol()
{
    local symbol=$1
    shift
    local file
    local prefix
    local prefix_list

    for file in "$@"; do
        # For speed, lets just grep through the file. The symbol may
        # be of any of these forms:
        #     #define SYMBOL
        #     typedef void (SYMBOL)(void)
        #     extern void SYMBOL(void)
        #     void (*SYMBOL)(void)
        #     enum { SYMBOL, } void
        #
        # Since 3.7 headers can be in both $KBUILD_SRC/include
        #     or $KBUILD_SRC/include/uapi so check both
        # If the file contains "include/linux" then build set of
        # prefixes

        prefix=$(dirname $file)
        file=$(basename $file)
        if [ "$prefix" == "include/linux" ]; then
            prefix_list="include/linux/ include/uapi/linux/"
        else
            prefix_list="$prefix/"
        fi

        for prefix in $prefix_list; do
            if [ -n "${OFA_KSRC:-}" ]; then
                if [ $verbose = true ]; then
                    echo >&2 "Looking for '$symbol' in '$OFA_KSRC/$prefix$file'"
                fi

                [ -f "$OFA_KSRC/$prefix$file" ] &&  \
                strip_comments $OFA_KSRC/$prefix$file | \
                egrep -w "$symbol" >/dev/null && \

                return 0
            fi

            if [ $verbose = true ]; then
                echo >&2 "Looking for '$symbol' in '$KBUILD_SRC/$prefix$file'"
            fi

            [ -f "$KBUILD_SRC/$prefix$file" ] &&  \
            strip_comments $KBUILD_SRC/$prefix$file | \
            egrep -w "$symbol" >/dev/null && \

            return 0
        done
    done
    return 1
}

function defer_test_symtype()
{
    local sense=$1
    local symbol=$2
    local file=$3
    shift 3
    local type="$*"

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <linux/types.h>
#include <${file:8}>

#include \"_autocompat.h\"

__typeof($type) *kernel_compat_dummy = &$symbol;
"
}

function defer_test_member()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_member() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
extern void kernel_compat_dummy_func(void);
void kernel_compat_dummy_func(void) {
$aggtype kernel_compat_dummy = { .$memname = kernel_compat_dummy.$memname };
}
"
}

function defer_test_memtype()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4
    local memtype="$*"

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
__typeof($memtype) *kernel_compat_dummy_2 = &kernel_compat_dummy_1.$memname;
"
}

function defer_test_bitfield()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_bitfield() only works in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
unsigned long test(void) {
    return kernel_compat_dummy_1.$memname;
}
"
}

function test_inline_symbol()
{
    local symbol=$1
    local file=$2
    local t=$(mktemp)
    rmfiles="$rmfiles $t"

    if [ -n "${OFA_KSRC:-}" ]; then
        [ -f "$OFA_KSRC/$file" ] &&
        [ -f "$KBUILD_SRC/$file" ] || return
    fi

    # TODO: This isn't very satisfactory. Alternative options are:
    #   1. Come up with a clever sed version
    #   2. Do a test compile, and look for an undefined symbol (extern)

    # look for the inline..symbol. This is complicated since the inline
    # and the symbol may be on different lines.
    if [ -n "${OFA_KSRC:-}" ]; then
        strip_comments $OFA_KSRC/$file | \
        egrep -m 1 -B 1 '(^|[,\* \(])'"$symbol"'($|[,; \(\)])' > $t
           [ $? = 0 ] || return $?

        # there is either an inline on the final line, or an inline and
        # no semicolon on the previous line
        head -1 $t | egrep -q 'inline[^;]*$' && return
        tail -1 $t | egrep -q 'inline' && return

        strip_comments $KBUILD_SRC/$file | \
        egrep -m 1 -B 1 '(^|[,\* \(])'"$symbol"'($|[,; \(\)])' > $t

        [ $? = 0 ] || return $?

        # there is either an inline on the final line, or an inline and
        # no semicolon on the previous line
        head -1 $t | egrep -q 'inline[^;]*$' && return
        tail -1 $t | egrep -q 'inline' && return
    fi

    return 1
}

function test_export()
{
    local symbol=$1
    shift
    local files="$@"
    local file match

    # Looks for the given export symbol $symbol, defined in $file
    # Since this symbol is exported, we can look for it in:
    #     1. $KBUILD_MODULE_SYMVERS
    #     2. If the full source is installed, look in there.
    #        May give a false positive if the export is conditional.
    #     3. The MAP file if present. May give a false positive
    #        because it lists all extern (not only exported) symbols.
    if [ -f $KBUILD_MODULE_SYMVERS ]; then
        if [ $verbose = true ]; then
            echo >&2 "Looking for export of $symbol in $KBUILD_MODULE_SYMVERS"
        fi
        [ -n "$(awk '/0x[0-9a-f]+[\t ]+'$symbol'[\t ]+/' $KBUILD_MODULE_SYMVERS)" ]
    else
        for file in $files; do
            if [ -n "${OFA_KSRC:-}" ]; then
                if [ $verbose = true ]; then
                    echo >&2 "Looking for export of $symbol in $OFA_KSRC/$file"
                fi
                if [ -f $OFA_KSRC/$file ]; then
                    egrep -q 'EXPORT_(PER_CPU)?SYMBOL(_GPL)?\('"$symbol"'\)' $OFA_KSRC/$file && return
                fi

                if [ $verbose = true ]; then
                    echo >&2 "Looking for export of $symbol in $KBUILD_SRC/$file"
                fi
                if [ -f $KBUILD_SRC/$file ]; then
                    egrep -q 'EXPORT_(PER_CPU)?SYMBOL(_GPL)?\('"$symbol"'\)' $KBUILD_SRC/$file && return
                fi
            fi
        done
        if [ -n "$MAP" ]; then
            if [ $verbose = true ]; then
                echo >&2 "Looking for export of $symbol in $MAP"
            fi
            egrep -q "[A-Z] $symbol\$" $MAP && return
        fi
        return 1
    fi
}

function test_compile()
{
    local source="$1"
    local rc
    local dir=$(mktemp -d)
    echo "$source" > $dir/test.c
    cat > $dir/Makefile <<EOF
$makefile_prefix
obj-m := test.o
EOF
    if [ -n "${LINUXINCLUDE:-}" ]; then
        make -rR CROSS_COMPILE=$CROSS_COMPILE -C $KPATH ARCH=$ARCH \
        LINUXINCLUDE="$LINUXINCLUDE" M=$dir O=$KOUT ${CC:+CC="$CC"} >$dir/log 2>&1
    else
        make -rR CROSS_COMPILE=$CROSS_COMPILE -C $KPATH ARCH=$ARCH \
        M=$dir O=$KOUT ${CC:+CC="$CC"} >$dir/log 2>&1
    fi
    rc=$?

    if [ $verbose = true ]; then
        echo >&2 "tried to compile:"
        sed >&2 's/^/    /' $dir/test.c
        echo >&2 "compiler output:"
        sed >&2 's/^/    /' $dir/log
    fi

    rm -rf $dir
    return $rc
}

function defer_test_compile()
{
    local sense=$1
    local source="$2"
    echo "$source" > "$compile_dir/test_$key.c"
    echo "obj-m += test_$key.o" >> "$compile_dir/Makefile"
    eval deferred_$sense=\"\$deferred_$sense $key\"
    return $DEFERRED
}

function read_make_variables()
{
    local regexp=''
    local split='('
    local variable
    local variables="$@"
    local dir=$(mktemp -d)
    for variable in $variables; do
    echo "\$(warning $variable=\$($variable))" >> $dir/Makefile
    regexp=$regexp$split$variable
    split='|'
    done
    if [ -n "${LINUXINCLUDE:-}" ]; then
        make -C $KPATH $EXTRA_MAKEFLAGS O=$KOUT \
        LINUXINCLUDE="$LINUXINCLUDE" M=$dir \
        2>&1 >/dev/null | sed -r "s#$dir/Makefile:.*: ($regexp)=.*$)#\1#; t; d"
    else
        make -C $KPATH $EXTRA_MAKEFLAGS O=$KOUT M=$dir \
        2>&1 >/dev/null | sed -r "s#$dir/Makefile:.*: ($regexp)=.*$)#\1#; t; d"
    fi
    rc=$?

    rm -rf $dir
    return $rc
}

function read_define()
{
    local variable="$1"
    local file="$2"
    cat $KOUT/$2 | sed -r 's/#define '"$variable"' (.*)/\1/; t; d'
}

quiet=false
verbose=false

KVER=
KPATH=
KOUT=
FILTER=
MAP=
EXTRA_MAKEFLAGS=
kompat_symbols=
ARCH=
CROSS_COMPILE=
LINUXINCLUDE=
OFA_KSRC=

# These variables from an outer build will interfere with our test builds
unset KBUILD_EXTMOD
unset KBUILD_SRC
unset M
unset TOPDIR
unset sub_make_done
unset OFA_KSRC

# Filter out make options except for job-server (parallel make)
old_MAKEFLAGS="${MAKEFLAGS:-}"
MAKEFLAGS=
next=
for word in $old_MAKEFLAGS; do
    case "$word" in
    '-j' | '-l')
        export MAKEFLAGS="$MAKEFLAGS $word"
        next=1
        ;;
    '-j'* | '-l'*)
        export MAKEFLAGS="$MAKEFLAGS $word"
        ;;
    '--jobserver-fds'* | '--jobs='* | '--jobs' | '--load-average'*)
        export MAKEFLAGS="$MAKEFLAGS $word"
        ;;
    *)
        test -n "$next" && export MAKEFLAGS="$MAKEFLAGS $word"
        next=
        ;;
    esac
done

# Clean-up temporary files when we exit.
rmfiles=
trap atexit_cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
    -a) ARCH=$2; shift;;
    -c) CROSS_COMPILE=$2; shift;;
    -f) OFA_KSRC=$2; shift;;
    -r) KVER=$2; shift;;
    -i) LINUXINCLUDE=$2; shift;;
    -k) KPATH=$2; shift;;
    -o) KOUT=$2; shift;;
    -q) quiet=true;;
    -m) MAP=$2; shift;;
    -v) verbose=true;;
    -s) kompat_symbols="$2"; shift;;
    -*) usage; exit -1;;
    *)  [ -z $FILTER ] && FILTER=$1 || FILTER="$FILTER|$1";;
    *)  break;
    esac
    shift
done

vmsg "MAKEFLAGS  := $MAKEFLAGS"

# resolve KVER and KPATH
[ -z "$KVER" ] && [ -z "$KPATH" ] && KVER=`uname -r`
[ -z "$KPATH" ] && KPATH=/lib/modules/$KVER/build
[ -z "$KOUT" ] && KOUT="$KPATH"

# Need to set CC explicitly on the kernel make line
# Needs to override top-level kernel Makefile setting
# Somehow this script does the wrong thing when a space is used in $CC,
# particularly when ccache is used, so disable that.
if [ -n "${CC:-}" ]; then
    CC=${CC/ccache /}
    CC=${CC/ /}
    EXTRA_MAKEFLAGS=CC=${CC}
fi

if [ -n "${CROSS_COMPILE:-}" ]; then
    EXTRA_MAKEFLAGS="${EXTRA_MAKEFLAGS} CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH}"
elif [ "${ARCH}" = "aarch64" ] || [ "${ARCH}" = "arm64" ]; then
	CROSS_COMPILE="${CC%-gcc}-"
	EXTRA_MAKEFLAGS="${EXTRA_MAKEFLAGS} CROSS_COMPILE=${CROSS_COMPILE} ARCH=${ARCH}"
fi

vmsg "EXTRA_MAKEFLAGS  := $EXTRA_MAKEFLAGS"
vmsg "ARCH             := ${ARCH}"
vmsg "CROSS_COMPILE    := ${CROSS_COMPILE}"

# Select the right warnings - complicated by working out which options work
makefile_prefix='
ifndef try-run
try-run = $(shell set -e;       \
    TMP="$(obj)/.$$$$.tmp";     \
    TMPO="$(obj)/.$$$$.o";      \
    if ($(1)) >/dev/null 2>&1;  \
    then echo "$(2)";       \
    else echo "$(3)";       \
    fi;             \
    rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
    $(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
EXTRA_CFLAGS = -Werror $(call cc-disable-warning, unused-but-set-variable)
'

# Ensure it looks like a build tree and we can build a module
[ -d "$KPATH" ] || fail "$KPATH is not a directory"
[ -f "$KPATH/Makefile" ] || fail "$KPATH/Makefile is not present"

[ -z "$ARCH" ] && ARCH="$(uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
                                  -e s/sun4u/sparc64/ \
                                  -e s/arm.*/arm/ -e s/sa110/arm/ \
                                  -e s/s390x/s390/ -e s/parisc64/parisc/ \
                                  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
                                  -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/)"

test_compile "#include <linux/module.h>
MODULE_LICENSE(\"GPL\");" || \
    fail "Kernel build tree is unable to build modules"

# strip the KVER out of UTS_RELEASE, and compare to the specified KVER
_KVER=
for F in include/generated/utsrelease.h include/linux/utsrelease.h include/linux/version.h; do
    [ -f $KOUT/$F ] && _KVER="$(eval echo $(read_define UTS_RELEASE $F))" && break
done
[ -n "$_KVER" ] || fail "Unable to identify kernel version from $KOUT"
if [ -n "$KVER" ]; then
    [ "$KVER" = "$_KVER" ] || fail "$KOUT kernel version $_KVER does not match $KVER"
fi
KVER=$_KVER
unset _KVER

vmsg "KVER       := $KVER"
vmsg "KPATH      := $KPATH"

# Define:
#     KBUILD_SRC:         Was renamed into abs_srctree in linux-5.3
#     KBUILD_SRC:         If not already set, same as KPATH
#     SRCARCH:            If not already set, same as ARCH
#     WORDSUFFIX:         Suffix added to some filenames by the i386/amd64 merge
[ -n "${KBUILD_SRC:-}" ] || KBUILD_SRC=${abs_srctree:-}
[ -n "${KBUILD_SRC:-}" ] || KBUILD_SRC=$KPATH
[ -n "${SRCARCH:-}" ] || SRCARCH=$ARCH
if [ "$ARCH" = "i386" ] || [ "${CONFIG_X86_32:-}" = "y" ]; then
    WORDSUFFIX=_32
elif [ "$ARCH" = "x86_64" ] || [ "${CONFIG_X86_64:-}" = "y" ]; then
    WORDSUFFIX=_64
else
    WORDSUFFIX=
fi
[ -f "$KBUILD_SRC/arch/$SRCARCH/Makefile" ] || fail "$KBUILD_SRC doesn't directly build $SRCARCH"

vmsg "KBUILD_SRC := $KBUILD_SRC"
vmsg "SRCARCH    := $SRCARCH"
vmsg "WORDSUFFIX := $WORDSUFFIX"

if [ -f "$KPATH/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS=$KPATH/Module.symvers
elif [ -n "${O:-}" -a -f "${O:-}/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS="$O/Module.symvers"
elif [ -f "$PWD/Module.symvers" ] ; then
    KBUILD_MODULE_SYMVERS="$PWD/Module.symvers"
else
    KBUILD_MODULE_SYMVERS=""
fi
vmsg "KBUILD_MODULE_SYMVERS := $KBUILD_MODULE_SYMVERS"

# try and find the System map [used by test_export]
if [ -z "$MAP" ]; then
    if [ -f /boot/System.map-$KVER ]; then
    MAP=/boot/System.map-$KVER
    elif [ $KVER = "`uname -r`" ] && [ -f /proc/kallsyms ]; then
    MAP=/proc/kallsyms
    elif [ -f $KBUILD_MODULE_SYMVERS ]; then
    # can use this to find external symbols only
    true
    else
    log "!!Unable to find a valid System map. Export symbol checks may not work"
    fi
fi

if [ "$kompat_symbols" == "" ]; then
    kompat_symbols="$(generate_kompat_symbols)"
fi

# filter the available symbols
if [ -n "$FILTER" ]; then
    kompat_symbols="$(echo "$kompat_symbols" | egrep "^($FILTER):")"
fi

compile_dir="$(mktemp -d)"
rmfiles="$rmfiles $compile_dir"
echo >"$compile_dir/Makefile" "$makefile_prefix"
echo >"$compile_dir/_autocompat.h"
deferred_pos=
deferred_neg=

# Note that for deferred tests this runs after the Makefile has run all tests
function do_one_symbol() {
    local key=$1
    shift
    # NB work is in the following if clause "do_${method}"
    if "$@"; then
    echo "#define $key yes"
    # So that future compile tests can consume this
    echo "#define $key yes" >> "${compile_dir}/_autocompat.h"
    elif [ $? -ne $DEFERRED ]; then
    echo "// #define $key"
    fi
}

# process each symbol
for symbol in $kompat_symbols; do
    # split symbol at colons; disable globbing (pathname expansion)
    set -o noglob
    IFS=:
    set -- $symbol
    unset IFS
    set +o noglob

    key="$1"
    method="$2"
    do_one_symbol $key do_${method} "$@"
done

function deferred_compile() {
    if [ -n "${LINUXINCLUDE:-}" ]; then
        make -C $KPATH -k $EXTRA_MAKEFLAGS O="$KOUT" \
        LINUXINCLUDE="$LINUXINCLUDE" M="$compile_dir" \
        >"$compile_dir/log" 2>&1 \
        || true
    else
        make -C $KPATH -k $EXTRA_MAKEFLAGS O="$KOUT" M="$compile_dir" \
        >"$compile_dir/log" 2>&1 \
        || true
    fi

    if [ $verbose = true ]; then
        echo >&2 "compiler output:"
        sed >&2 's/^/    /' "$compile_dir/log"
    fi
    for key in $deferred_pos; do
        # Use existence of object file as evidence of compile without warning/errors
        do_one_symbol $key test -f "$compile_dir/test_$key.o"
    done
    for key in $deferred_neg; do
        do_one_symbol $key test ! -f "$compile_dir/test_$key.o"
    done
}

# Run the deferred compile tests
deferred_compile
