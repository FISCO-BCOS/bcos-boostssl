#!/bin/bash
dirpath="$(cd "$(dirname "$0")" && pwd)"
cd "${dirpath}"

set -e

LOG_WARN() {
    local content=${1}
    echo -e "\033[31m[WARN] ${content}\033[0m"
}

LOG_INFO() {
    local content=${1}
    echo -e "\033[32m[INFO] ${content}\033[0m"
}

LOG_FALT() {
    local content=${1}
    echo -e "\033[31m[ERROR] ${content}\033[0m"
    exit 1
}

dir_must_exists() {
    if [ ! -d "$1" ]; then
        LOG_FALT "$1 DIR does not exist, please check!"
    fi
}

file_must_not_exists() {
    if [ -f "$1" ]; then
        LOG_FALT "$1 file already exist, please check!"
    fi
}

help() {
    cat <<EOF
Usage:
    -s <SM model>                       [Optional] SM SSL connection or not, default no
    -h Help
e.g
    bash $0 -s"
EOF

    exit 0
}

ssl_type="ssl"
config_file_name="boostssl.ini"
output_dir=${dirpath}

parse_params() {
    while getopts "sh" option; do
        case $option in
        s) ssl_type="sm_ssl" ;;
        h) help ;;
        *) help ;;
        esac
    done
}

print_result() {
    echo "=============================================================="
    LOG_INFO "SSL Model             : ${ssl_type}"
    LOG_INFO "All completed. Files in ${output_dir}"
}

generate_config_ini() {
    local output=${1}

    cat <<EOF >"${output}"
[common]
    ; ssl or sm_ssl
    ssl_type=ssl

[cert]
    ; directory the certificates located in
    ca_path=./
    ; the ca certificate file
    ca_cert=ca.crt
    ; the node private key file
    node_key=node.key
    ; the node certificate file
    node_cert=node.crt
EOF
}

generate_sm_config_ini() {
    local output=${1}

    cat <<EOF >"${output}"
[common]
    ; ssl or sm_ssl
    ssl_type=sm_ssl

[cert]
    ; directory the certificates located in
    ca_path=./
    ; the ca certificate file
    sm_ca_cert=sm_ca.crt
    ; the node private key file
    sm_node_key=sm_node.key
    ; the node certificate file
    sm_node_cert=sm_node.crt
    ; the node private key file
    sm_ennode_key=sm_ennode.key
    ; the node certificate file
    sm_ennode_cert=sm_ennode.crt
EOF
}

parse_params "$@"
file_must_not_exists "${output_dir}/${config_file_name}"

if [ "${ssl_type}" == "ssl" ]; then
    generate_config_ini "${output_dir}/${config_file_name}"
else
    generate_sm_config_ini "${output_dir}/${config_file_name}"
fi

print_result
