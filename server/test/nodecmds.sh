#!/bin/sh

set -o nounset

sx_killall()
{
    echo "Killing old processes"
    pkill -f sxhttpd 2>/dev/null || true
    pkill -9 -f sx.fcgi 2>/dev/null || true
}

sx_init() {
    if [ "$(id -u)" -eq 0 ]; then
        echo "You must NOT be root"
        return 1
    fi

    # for valgrind, avoid aes_ni warnings
    export OPENSSL_ia32cap="~0x200000000000000"

    export ASAN_OPTIONS=log_path=/tmp/asan.log

    ulimit -c unlimited

    if [ "$(uname)" = "OpenBSD" ]; then
        echo "Raise these limits if needed:"
        sysctl kern.maxlocksperuid kern.maxfiles
    fi

    # Cluster defaults
    CLUSTER_NAME=sxtest
    ADMIN_KEY=0DPiKuNIrrVmD8IUCuw1hQxNqZc8kneQi3GoAPaxWgJng4mcDWfj8QAA
    CLUSTER_UUID=f2d5c774-b40e-4bbf-88fc-9ccaa8a9e8af
    CLUSTER_BASE_URL="sx://admin@$CLUSTER_NAME"
    SX_PORT=9080
    ROOT="$(pwd)/test-sx"
}

sx_wipe()
{
    rm -rf "$ROOT"
    sx_killall
}

set_node_vars()
{
    i="$1"
    prefix=$ROOT/$i
    CONF_TMP="$prefix/conf.tmp"
}

load_node_vars()
{
    set_node_vars "$1"
    . "$prefix/etc/sxserver/sxsetup.conf"
}

sx_install_nodes()
{

    N="$1"
    i=1
    while [ $i -le "$N" ]; do
        echo
        echo "Preparing node $i"
        set_node_vars "$i"
        echo "Installing nginx config and scripts to $prefix"
        (cd sxscripts && make -e clean install prefix="$prefix" -s)
        mkdir -p "$prefix/bin" "$prefix/sbin $prefix/lib"
        ln -s "$(pwd)/../client/src/tools/init/sxinit" "$prefix/bin/sxinit"
        ln -s "$(pwd)/src/tools/sxadm/sxadm" "$prefix/sbin/sxadm"
        ln -s "$(pwd)/src/fcgi/sx.fcgi" "$prefix/sbin/sx.fcgi"
        cp "$prefix/etc/sxserver/sxhttpd.conf.default" "$prefix/etc/sxserver/sxhttpd.conf"

        # Run them once to have the compiler create .libs/lt-*
        "$prefix/bin/sxinit" --version
        "$prefix/sbin/sxadm" --version
        "$prefix/sbin/sx.fcgi" --version

        ln -s "$(pwd)/../3rdparty/sxhttpd/build-nginx/objs/nginx" "$prefix/sbin/sxhttpd"
        sed -e "s|\(/sx.fcgi\)|\1 --config-file $prefix/etc/sxserver/sxfcgi.conf|" "$prefix/sbin/sxserver" >tmp
        mv tmp "$prefix/sbin/sxserver"
        chmod +x "$prefix/sbin/sxserver"

        cat >>"$CONF_TMP" <<EOF
        SX_CFG_VERSION=3
        SX_CLUSTER_NAME="$CLUSTER_NAME"
        SX_DATA_DIR="$prefix/var/lib/sxserver/storage"
        SX_RUN_DIR="$prefix/var/run/sxserver"
        SX_LIB_DIR="$prefix/var/lib/sxserver"
        SX_LOG_FILE="$prefix/var/log/sxserver/sxfcgi.log"
        SX_NODE_SIZE="1T"
        SX_NODE_IP="127.0.1.$i"
        SX_SERVER_USER=$(id -n -u)
        SX_PORT="$SX_PORT"
        SX_USE_SSL="no"
        SX_CLUSTER_UUID="$CLUSTER_UUID"
        SX_ADMIN_KEY="$ADMIN_KEY"
        SX_CHILDREN_NUM=4
        SX_RESERVED_CHILDREN_NUM=3
EOF
        if [ $i -gt 1 ]; then
	    echo "SX_EXISTING_NODE_IP=\"127.0.1.1\"" >> "$CONF_TMP"
        fi

        i=$(( i+1 ))
    done
}

sx_node_new_bare()
{
    load_node_vars 1
    set_node_vars "$1"
    echo "SX_CLUSTER_KEY=$SX_CLUSTER_KEY" >>"$CONF_TMP"
    "$prefix/sbin/sxsetup" --config-file "$CONF_TMP" --advanced --bare
}

sx_node_new_join()
{
    set_node_vars "$1"
    set -x
    SX_EXISTING_NODE_IP=$(ls -1 "${HOME}/.sx/${CLUSTER_NAME}/nodes" | head -n 1)
    sed -e "s^SX_EXISTING_NODE_IP=.*^SX_EXISTING_NODE_IP=\"$SX_EXISTING_NODE_IP\"^" "$CONF_TMP" >tmp
    mv tmp "$CONF_TMP"
    set +x
    "$prefix/sbin/sxsetup" --config-file "$CONF_TMP" --advanced --wait
}

sx_wait_rebalance()
{
    load_node_vars 1 || return 1
    while true; do
        sx_cluster_info >tmp || { cat tmp; sleep 1; continue; }
        if grep 'Target configuration' tmp >/dev/null; then
            echo "Waiting for rebalance to finish ..."
            cat tmp
            sleep 1
            continue
        fi
        break
    done
}

sx_node_remove()
{
    load_node_vars "$1" || return 1
    SXSETUP_BATCH_MODE=yes "$prefix/sbin/sxsetup" --advanced --deactivate
}

sx_node_stop()
{
    set_node_vars "$1"
    "$prefix/sbin/sxserver" stop
}

sx_node_start()
{
    set_node_vars "$1"
    "$prefix/sbin/sxserver" start
}

sx_node_def()
{
    load_node_vars "$1" || return 1
    "$prefix/sbin/sxadm" node --get-definition "$SX_DATA_DIR"
}

sx_cluster_info()
{
    set_node_vars 1
    "$prefix/sbin/sxadm" cluster --info "$CLUSTER_BASE_URL"
}

sx_node_setfaulty()
{
    sx_node_stop "$1"
    "$prefix/sbin/sxadm" cluster --set-faulty "$(sx_node_def "$1")" "$CLUSTER_BASE_URL"
}

sx_node_replace()
{
    unset OLD_UUID
    load_node_vars "$1"
    OLD_UUID=$("$prefix/sbin/sxadm" node --get-definition "$SX_DATA_DIR" | cut -f4 -d/)

    sx_node_new_bare "$2" || true
    load_node_vars "$2"
    "$prefix/sbin/sxadm" cluster --replace-faulty "$SX_NODE_SIZE/$SX_NODE_IP/$OLD_UUID" "$CLUSTER_BASE_URL"

    sx_wait_rebalance
}

sx_node_info()
{
    load_node_vars "$1"
    "$prefix/sbin/sxadm" node --info "$SX_DATA_DIR"
}

sx_create_cluster()
{
    N="$1"
    sx_init
    sx_wipe
    sx_install_nodes "$N"

    i=1
    while [ $i -le "$N" ]; do
        sx_node_new_join "$i"
        i=$(( i+1 ))
    done
}

sx_create_whole_cluster()
{
    CLUSTER_NODES="$1"
    CLUSTER_ALL="$2"
    sx_init
    sx_wipe
    sx_install_nodes "$CLUSTER_ALL"

    sx_node_new_join 1
    i=2
    while [ $i -le "$CLUSTER_NODES" ]; do
        sx_node_new_bare "$i"
        i=$(( i+1 ))
    done

    DIST="$(sx_node_def 1)"
    i=2
    while [ $i -le "$CLUSTER_NODES" ]; do
        load_node_vars "$i"
        DIST="$DIST $SX_NODE_SIZE/$SX_NODE_IP"
        i=$(( i+1 ))
    done

    set_node_vars 1
    "$prefix/sbin/sxadm" cluster --mod $DIST "$CLUSTER_BASE_URL"

    sx_wait_rebalance
    sx_cluster_info
}
