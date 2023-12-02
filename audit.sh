#!/bin/bash
#Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 
#Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.
#Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.
#For more information, please refer to https://www.web3password.com/web3password_license.txt


SCRIPT_NAME="audit.sh"  
SCRIPT_VERSION="1.0"  
SCRIPT_AUTHOR="Web3Password"  
SCRIPT_DESC="Interface Audit Scripts. Using this script, you can easily view the information encrypted in the interface, but of course, you must enter your own mnemonic to decrypt the view."  
  
# main() {  
#   local mnemonic=""  
#   local logstr=""  
#   local logdir=""  
  
#   mnemonic="$1"  
#   logstr="$2"  
#   logdir="$3"  
  
#   if [[ -z "$logstr" && -z "$logdir" ]]; then  
#     echo "Error: Please provide at least one of -logstr or -logdir."  
#     exit 1  
#   fi  
  
# #   echo "${mnemonic#*=}"
  
#   node Web3Password-Tools/web3password-api-audit.js "${mnemonic#*=}" "${logstr#*=}" "${logdir#*=}"

#   exit 0  
# }  
  
# main "$1" "$2" "$3"
main() {  
    mnemonic="$1"  
    data="$2"  
    if [ -z "$1" ]; then  
        echo "please input your mnemonic"  
        exit 1  
    fi

    if [ -z "$2" ]; then  
        echo "please input data"  
        exit 1  
    fi  

    node Web3Password-Tools/web3password-api-audit.js "$mnemonic" "$data"

    exit 0
}  
main "$@"
