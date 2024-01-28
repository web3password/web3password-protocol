/*
Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/


const { ethers, BigNumber } = require("ethers");
const fs = require('fs');  
const readline = require('readline');  

// https://github.com/mongodb/js-bson#bugs--feature-requests
const { BSON, EJSON, ObjectId, Binary } = require('bson');


// uuidv4();
const { v4: uuidv4 } = require('uuid');
const {gzip, ungzip} = require('node-gzip');

const crypto = require('crypto');
const buffer = require('buffer');

const {Web3PasswordSleep2, aesEncryptBson, aesDecryptBson, chacha20poly1305EncryptBson, chacha20poly1305DecryptBson, Web3PasswordRequestEncodeBsonApi, Web3PasswordRequestDecodeBsonApi, } = require("./web3password-lib");
const { exit } = require("process");

const Web3PasswordMnemonicTest = process.argv[2].trim();
const satislogfile = process.argv[3];
if (Web3PasswordMnemonicTest.length <=0 || data.length <=0) {
    console.log("params error");
    exit(1);
}

const hdNode = ethers.utils.HDNode.fromMnemonic(Web3PasswordMnemonicTest);

let basePath = "m/44'/60'/0'/0";
let addressIndex = 0; // primary address/primary key
let hdNodeNew = hdNode.derivePath(basePath + "/" + addressIndex);
const wallet0 = new ethers.Wallet(hdNodeNew.privateKey);

const main = async () => {
    try {  
            console.log(satislogfile)
            const fileStream = fs.createReadStream(satislogfile);  
            const rl = readline.createInterface({  
                input: fileStream,  
                crlfDelay: Infinity  
            });
        
            
            for await (const line of rl) {
                const line = recentLines[i];  
                const jsonData = JSON.parse(line);  
                if (jsonData.audit_log == "") {
                    continue;
                }


                let address0 = await wallet0.getAddress();
                const publicKey0 = wallet0.publicKey;
                const privateKey0 = wallet0.privateKey;
                // console.log("address0: ", address0);
                // console.log("publicKey0: ", publicKey0);
                // console.log("privateKey0: ", privateKey0);
        
                console.log(`----------------------------- web3password api decode start-----------------------------------`);
                const w3pAddCredentialRequestBase64Str = jsonData.audit_log
                const w3pAddCredentialRequestBytes = Buffer.from(w3pAddCredentialRequestBase64Str, "base64");
        
                const w3pAddCredentialRequestObject = await Web3PasswordRequestDecodeBsonApi(w3pAddCredentialRequestBytes);
        
                // console.log("signature length: ", w3pAddCredentialRequestObject.signature.length);
                // console.log("signature: ", w3pAddCredentialRequestObject.signature);
                // console.log("params length: ", w3pAddCredentialRequestObject.params.length);
                // console.log("params: ", w3pAddCredentialRequestObject.params);
                // console.log("append length: ", w3pAddCredentialRequestObject.data.length);
                // console.log("append Hex: ", w3pAddCredentialRequestObject.data.toString("hex"));

                const params = JSON.parse(w3pAddCredentialRequestObject.params);  
                if (params.addr.toLowerCase() != address0.toLowerCase()) {
                    console.log(`not your UserID: ${params.addr}, skip...`);
                    continue;
                }

                
                if (jsonData.msg != "/web3password/addCredential") {
                    console.log(w3pAddCredentialRequestObject);
                } else {
                    console.log("----------------------------- decrypt start -----------------------------");
                    console.log("---------- first chacha20 decrypt --------------");
                    const chacha20BsonBytes = w3pAddCredentialRequestObject.data;
                    const chacha20BsonObject = BSON.deserialize(chacha20BsonBytes)
                    let chacha20AddressIndex = chacha20BsonObject.id
                    let hdNodeNew1 = hdNode.derivePath(basePath + "/" + chacha20AddressIndex);
                    const wallet1 = new ethers.Wallet(hdNodeNew1.privateKey);
                    const publicKey1 = wallet1.publicKey;
                    const privateKey1 = wallet1.privateKey;
                    const chacha20Key = privateKey1.substring(2);
                    console.log("algoSimpleName: ", chacha20BsonObject.cn);
                    console.log("chacha20 id: ", chacha20AddressIndex);
                    console.log("chacha20 key: ", chacha20Key);
        
                    const aesBsonBytes = await chacha20poly1305DecryptBson(chacha20Key, chacha20BsonBytes);
                    console.log("---------- second aes decrypt ----------------");
                    const aesBsonObject = BSON.deserialize(aesBsonBytes);
                    let aesAddressIndex = aesBsonObject.id
                    let hdNodeNew2 = hdNode.derivePath(basePath + "/" + aesAddressIndex);
                    const wallet2 = new ethers.Wallet(hdNodeNew2.privateKey);
                    const publicKey2 = wallet2.publicKey;
                    const privateKey2 = wallet2.privateKey;
                    const aesKey = privateKey2.substring(2);
                    console.log("algoSimpleName: ", aesBsonObject.cn);
                    console.log("aes id: ", aesAddressIndex);
                    console.log("aes key: ", aesKey);
                    const rawCredentialBytes = await aesDecryptBson(aesKey, aesBsonBytes);
                    console.log(`rawCredentialBytes Length: `, rawCredentialBytes.length);
                    console.log(`rawCredentialBytes to Str: `, rawCredentialBytes.toString("utf-8"));
                    console.log("----------------------------- decrypt end -----------------------------");
                }
        
                console.log(`----------------------------- web3password api decode end-----------------------------------`);
        }  

        

    } catch (err) {
        console.log(err.message);
    }
};

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
