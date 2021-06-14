#!/bin/bash
dirpath="$(cd "$(dirname "$0")" && pwd)"
cd "${dirpath}"

#set -e

ca_cert_dir="${dirpath}"
output_dir="${dirpath}"
cert_conf='cert.cnf'
sm_cert_conf='sm_cert.cnf'
generate_ca='true'
days=36500
rsa_key_length=2048
sm_model='false'
macOS=""
x86_64_arch="true"
sm2_params="sm_sm2.param"
cdn_link_header="https://osp-1257653870.cos.ap-guangzhou.myqcloud.com/FISCO-BCOS"
TASSL_CMD="${HOME}"/.fisco/tassl

help() {
    echo $1
    cat <<EOF
Usage: 
    -c <dir>                            [Optional] the ca cert dir path, working with '-n', default: './'
    -d <dir>                            [Required] generated output_dir
    -n                                  [Optional] generate node cert
    -s                                  [Optional] generate sm cert, default false
    -t                                  [Optional] cert.cnf path, default: cert.cnf for rsa cert and sm_cert.cnf for sm cert
    -h                                  [Optional] Help
e.g 
    bash $0 -d ./ca
    bash $0 -n -c ./ca -d ./ca/node
EOF

    exit 0
}

LOG_WARN() {
    local content=${1}
    echo -e "\033[31m[ERROR] ${content}\033[0m"
}

LOG_INFO() {
    local content=${1}
    echo -e "\033[32m[INFO] ${content}\033[0m"
}

LOG_FALT() {
    local content=${1}
    echo -e "\033[31m[FALT] ${content}\033[0m"
    exit 1
}

check_env() {
    [ ! -z "$(openssl version | grep 1.0.2)" ] || [ ! -z "$(openssl version | grep 1.1)" ] || [ ! -z "$(openssl version | grep reSSL)" ] || {
        #echo "download openssl from https://www.openssl.org."
        LOG_FALT "Use \"openssl version\" command to check."
    }
    if [ ! -z "$(openssl version | grep reSSL)" ]; then
        export PATH="/usr/local/opt/openssl/bin:$PATH"
    fi
    if [ "$(uname)" == "Darwin" ]; then
        macOS="macOS"
    fi
    if [ "$(uname -m)" != "x86_64" ]; then
        x86_64_arch="false"
    fi
}

check_and_install_tassl() {
    if [[ "${sm_model}" == "true" ]]; then
        if [ ! -f "${TASSL_CMD}" ]; then
            # TODO: add tassl v1.1 version binary exec
            local tassl_link_perfix="${cdn_link_header}/FISCO-BCOS/tools/tassl-1.0.2"
            LOG_INFO "Downloading tassl binary from ${tassl_link_perfix}..."
            if [[ -n "${macOS}" ]]; then
                curl -#LO "${tassl_link_perfix}/tassl_mac.tar.gz"
                mv tassl_mac.tar.gz tassl.tar.gz
            else
                if [[ "$(uname -p)" == "aarch64" ]]; then
                    curl -#LO "${tassl_link_perfix}/tassl-aarch64.tar.gz"
                    mv tassl-aarch64.tar.gz tassl.tar.gz
                elif [[ "$(uname -p)" == "x86_64" ]]; then
                    curl -#LO "${tassl_link_perfix}/tassl.tar.gz"
                else
                    LOG_ERROR "Unsupported platform: $(uname -p)"
                    exit 1
                fi
            fi
            tar zxvf tassl.tar.gz && rm tassl.tar.gz
            chmod u+x tassl
            mkdir -p "${HOME}"/.fisco
            mv tassl "${HOME}"/.fisco/tassl
        fi
    fi
}

check_name() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[a-zA-Z0-9._-]+$ ]] || {
        LOG_FALT "$name name [$value] invalid, it should match regex: ^[a-zA-Z0-9._-]+\$"
    }
}

file_must_exists() {
    if [ ! -f "$1" ]; then
        LOG_FALT "$1 file does not exist, please check!"
    fi
}

file_must_not_exists() {
    if [ -f "$1" ]; then
        LOG_FALT "$1 file exists, please check!"
    fi
}

dir_must_exists() {
    if [ ! -d "$1" ]; then
        LOG_FALT "$1 DIR does not exist, please check!"
    fi
}

dir_must_not_exists() {
    if [ -e "$1" ]; then
        LOG_FALT "$1 DIR exists, please clean old DIR!"
    fi
}

generate_sm_sm2_param() {
    local output=$1
    cat <<EOF >"${output}"
-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----

EOF
}

generate_sm_cert_conf() {
    local output=$1
    cat <<EOF >"${output}"
HOME			= .
RANDFILE		= $ENV::HOME/.rnd
oid_section		= new_oids

[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

dir		= ./demoCA		# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
#unique_subject	= no			# Set to 'no' to allow creation of
					# several ctificates with same subject.
new_certs_dir	= $dir/newcerts		# default place for new certs.

certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem # The private key
RANDFILE	= $dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extensions to add to the cert

name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

policy		= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 2048
default_md		= sm3
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
x509_extensions	= v3_ca	# The extensions to add to the self signed cert

string_mask = utf8only

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName = CN
countryName_default = CN
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default =GuangDong
localityName = Locality Name (eg, city)
localityName_default = ShenZhen
organizationalUnitName = Organizational Unit Name (eg, section)
organizationalUnitName_default = fisco
commonName =  Organizational  commonName (eg, fisco)
commonName_default =  fisco
commonName_max = 64

[ usr_cert ]
basicConstraints=CA:FALSE
nsComment			= "OpenSSL Generated Certificate"

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature

[ v3enc_req ]

# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = keyAgreement, keyEncipherment, dataEncipherment

[ v3_agency_root ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
keyUsage = cRLSign, keyCertSign

EOF
}

generate_cert_conf() {
    local output=$1
    cat <<EOF >"${output}"
[ca]
default_ca=default_ca
[default_ca]
default_days = 3650
default_md = sha256

[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
countryName = CN
countryName_default = CN
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default =GuangDong
localityName = Locality Name (eg, city)
localityName_default = ShenZhen
organizationalUnitName = Organizational Unit Name (eg, section)
organizationalUnitName_default = FISCO-BCOS
commonName =  Organizational  commonName (eg, FISCO-BCOS)
commonName_default = FISCO-BCOS
commonName_max = 64

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v4_req ]
basicConstraints = CA:TRUE

EOF
}

gen_chain_cert() {

    if [ ! -f "${cert_conf}" ]; then
        generate_cert_conf 'cert.cnf'
    else
        cp "${cert_conf}" .
    fi

    local chaindir="${1}"

    file_must_not_exists "${chaindir}"/ca.key
    file_must_not_exists "${chaindir}"/ca.crt
    file_must_exists 'cert.cnf'

    mkdir -p "$chaindir"
    dir_must_exists "$chaindir"

    openssl genrsa -out "${chaindir}"/ca.key "${rsa_key_length}"
    openssl req -new -x509 -days "${days}" -subj "/CN=FISCO-BCOS/O=FISCO-BCOS/OU=chain" -key "${chaindir}"/ca.key -out "${chaindir}"/ca.crt
    cp "cert.cnf" "${chaindir}"

    LOG_INFO "Build ca cert successfully!"
}

gen_rsa_node_cert() {
    local capath="${1}"
    local ndpath="${2}"
    local node="${3}"

    file_must_exists "$capath/ca.key"
    file_must_exists "$capath/ca.crt"
    check_name node "$node"

    file_must_not_exists "$ndpath"/node.key
    file_must_not_exists "$ndpath"/node.crt

    mkdir -p "${ndpath}"
    dir_must_exists "${ndpath}"

    openssl genrsa -out "${ndpath}"/node.key "${rsa_key_length}"
    openssl req -new -sha256 -subj "/CN=FISCO-BCOS/O=fisco-bcos/OU=agency" -key "$ndpath"/node.key -config "$capath"/cert.cnf -out "$ndpath"/ssl.csr
    openssl x509 -req -days "${days}" -sha256 -CA "${capath}"/ca.crt -CAkey "$capath"/ca.key -CAcreateserial \
        -in "$ndpath"/ssl.csr -out "$ndpath"/node.crt -extensions v4_req -extfile "$capath"/cert.cnf

    openssl pkcs8 -topk8 -in "$ndpath"/node.key -out "$ndpath"/pkcs8_node.key -nocrypt
    cp "$capath"/ca.crt "$capath"/cert.cnf "$ndpath"/

    rm -f "$ndpath"/ssl.csr
    rm -f "$ndpath"/node.key

    mv "$ndpath"/pkcs8_node.key "$ndpath"/node.key

    LOG_INFO "Build ${node} cert successful!"
}

gen_sm_chain_cert() {
    local chaindir="${1}"
    name=$(basename "$chaindir")
    check_name chain "$name"

    if [ ! -f "${sm_cert_conf}" ]; then
        generate_sm_cert_conf 'sm_cert.cnf'
    else
        cp -f "${sm_cert_conf}" .
    fi

    generate_sm_sm2_param "${sm2_params}"

    mkdir -p "$chaindir"
    dir_must_exists "$chaindir"

    "$TASSL_CMD" genpkey -paramfile "${sm2_params}" -out "$chaindir/sm_ca.key"
    "$TASSL_CMD" req -config sm_cert.cnf -x509 -days "${days}" -subj "/CN=FISCO-BCOS/O=FISCO-BCOS/OU=chain" -key "$chaindir/sm_ca.key" -extensions v3_ca -out "$chaindir/sm_ca.crt"
    cp "${sm_cert_conf}" "${chaindir}"
    cp "${sm2_params}" "${chaindir}"
}

gen_sm_node_cert_with_ext() {
    local capath="$1"
    local certpath="$2"
    local name="$3"
    local type="$4"
    local extensions="$5"

    file_must_exists "$capath/sm_ca.key"
    file_must_exists "$capath/sm_ca.crt"

    file_must_not_exists "$ndpath/sm_${type}.crt"
    file_must_not_exists "$ndpath/sm_${type}.key"

    "$TASSL_CMD" genpkey -paramfile "$capath/${sm2_params}" -out "$certpath/sm_${type}.key"
    "$TASSL_CMD" req -new -subj "/CN=$name/O=fisco-bcos/OU=${type}" -key "$certpath/sm_${type}.key" -config "$capath/sm_cert.cnf" -out "$certpath/sm_${type}.csr"

    echo "not use $(basename "$capath") to sign $(basename $certpath) ${type}" >>"${logfile}"
    "$TASSL_CMD" x509 -sm3 -req -CA "$capath/sm_ca.crt" -CAkey "$capath/sm_ca.key" -days "${days}" -CAcreateserial -in "$certpath/sm_${type}.csr" -out "$certpath/sm_${type}.crt" -extfile "$capath/sm_cert.cnf" -extensions "$extensions"

    rm -f "$certpath/sm_${type}.csr"
}

gen_sm_node_cert() {
    local capath="${1}"
    local ndpath="${2}"

    file_must_exists "$capath/sm_ca.key"
    file_must_exists "$capath/sm_ca.crt"

    mkdir -p "$ndpath"
    dir_must_exists "$ndpath"
    local node=$(basename "$ndpath")
    check_name node "$node"

    gen_sm_node_cert_with_ext "$capath" "$ndpath" "$node" node v3_req
    cat "${capath}/sm_ca.crt" >>"$ndpath/sm_node.crt"
    gen_sm_node_cert_with_ext "$capath" "$ndpath" "$node" ennode v3enc_req
    #nodeid is pubkey
    $TASSL_CMD ec -in "$ndpath/sm_node.key" -text -noout 2>/dev/null | sed -n '7,11p' | sed 's/://g' | tr "\n" " " | sed 's/ //g' | awk '{print substr($0,3);}' | cat >"$ndpath/sm_node.nodeid"

    #serial
    # if [ "" != "$($TASSL_CMD version 2>/dev/null | grep 1.0.2)" ]; then
    #    "$TASSL_CMD" x509 -text -in "$ndpath/sm_node.crt" 2>/dev/null | sed -n '5p' | sed 's/://g' | tr "\n" " " | sed 's/ //g' | sed 's/[a-z]/\u&/g' | cat >"$ndpath/sm_node.serial"
    # else
    #    "$TASSL_CMD" x509 -text -in "$ndpath/sm_node.crt" 2>/dev/null | sed -n '4p' | sed 's/ //g' | sed 's/.*(0x//g' | sed 's/)//g' | sed 's/[a-z]/\u&/g' | cat >"$ndpath/sm_node.serial"
    # fi

    cp "$capath/sm_ca.crt" "$ndpath"
}

while getopts "c:d:D:nst:h" option; do
    case $option in
    c) ca_cert_dir="$OPTARG" ;;
    d) output_dir="$OPTARG" ;;
    n) generate_ca='false' ;;
    s) sm_model='true' ;;
    t)
        cert_conf="$OPTARG"
        sm_cert_conf="$OPTARG"
        ;;
    *) help ;;
    esac
done

main() {
    if [[ "${sm_model}" == "false" ]]; then
        if [[ ${generate_ca} == 'true' ]]; then
            gen_chain_cert "${output_dir}" 2>&1
        else
            gen_rsa_node_cert "${ca_cert_dir}" "${output_dir}" "node" 2>&1
        fi
    else
        if [[ ${generate_ca} == 'true' ]]; then
            gen_sm_chain_cert "${output_dir}" 2>&1
        else
            gen_sm_node_cert "${ca_cert_dir}" "${output_dir}" "node" 2>&1
        fi
    fi

}

check_env
check_and_install_tassl
main
