#!/bin/bash
# Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 
# Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.
# Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.
# For more information, please refer to https://www.web3password.com/web3password_license.txt


WORK_DIR=`pwd`

SCRIPT_NAME="audit.sh"  
SCRIPT_VERSION="1.0"  
SCRIPT_AUTHOR="Web3Password"  
SCRIPT_DESC="Audit Web3Password API Communication"  

nodejs_url="https://nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.xz"

wget -c $nodejs_url -O /tmp/nodejs.tar.xz
if [ $? -ne 0 ] ; then
    echo "install nodejs failed..."
    exit 1
fi

NODEJS_DIR=/tmp/nodejs
mkdir -p ${NODEJS_DIR}
tar xvf /tmp/nodejs.tar.xz -C ${NODEJS_DIR}/ --strip-components 1
${NODEJS_DIR}/bin/node --version
if [ $? -ne 0 ] ; then
    echo "install nodejs failed..."
    exit 2
fi

export PATH=$PATH:${NODEJS_DIR}/bin
W3PTOOLS_DIR="${WORK_DIR}/Web3Password-Tools"

cd ${W3PTOOLS_DIR} && npm install
if [ $? -ne 0 ] ; then
    echo "install npm failed..."
    exit 3
fi

main() {  
    mnemonic="$1"  
    satis_logfile="$2"  
    if [ -z "$1" ]; then  
        echo "Usage: /bin/bash audit.sh your-mnemonic-phrase satis-logfile"
        exit 4
    fi

    if [ -z "$2" ]; then  
        echo "Usage: /bin/bash audit.sh your-mnemonic-phrase satis-logfile"
        exit 5  
    fi  

    node ${W3PTOOLS_DIR}/web3password-api-audit.js "$mnemonic" "$satis_logfile"

    exit 0
}  
main "$@"
