/*
Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

const { ethers, BigNumber } = require("ethers");
// https://github.com/mongodb/js-bson#bugs--feature-requests
const { BSON, EJSON, ObjectId, Binary } = require('bson');


// uuidv4();
const { v4: uuidv4 } = require('uuid');
const {gzip, ungzip} = require('node-gzip');

const crypto = require('crypto');
const buffer = require('buffer');

const fs = require('fs');

const {aesEncryptBson, aesDecryptBson, chacha20poly1305EncryptBson, chacha20poly1305DecryptBson} = require("./web3password-lib");


const Web3PasswordMnemonicTest = `pact ketchup salute simple gadget rude other embody infant object advance volcano guess library unfold bread public bind couple voyage host equip bubble clock`;


const hdNode = ethers.utils.HDNode.fromMnemonic(Web3PasswordMnemonicTest);

let basePath = "m/44'/60'/0'/0";
let i = 0; // primary address/primary key
let hdNodeNew = hdNode.derivePath(basePath + "/" + i);
const wallet0 = new ethers.Wallet(hdNodeNew.privateKey);


const main = async () => {
    try {
        let address0 = await wallet0.getAddress();
        const publicKey0 = wallet0.publicKey;
        const privateKey0 = wallet0.privateKey;
        console.log("address0: ", address0);
        console.log("publicKey0: ", publicKey0);
        console.log("privateKey0: ", privateKey0);
        // console.log("balance0: ", ethers.utils.formatEther(balance));

        let newBasePath = "m/44'/60'/0'/0";

        let id1 = 2;
        let dataSource = {
            "tp": "1", // data type: 1 Login， 2 bank card, 3 id card, 4  passport, 5 secure notes
            "te": "twitter-title - nodejs",
            "un": "musk@gmail.com - nodejs",
            "pw": "x:fNVZA,QZedam.x:fNVZA,QZedam.x:fNVZA,Q",
            "tt": "wqid s47z zgdl yq6w dsds flskddfs 232309u dkldfsa",  // 2factor
            "ur": ["https://www.twitter.com", "twitter.com", "com.twitter.android", "https://www.twitter.com/login"],
            "ns": "test-from-nodejs-bson",
        };


        console.log("================== nodejs bson encrypt/decrypt start ==================");
        const dataSourceStr = JSON.stringify(dataSource);
        const dataSourceBytes = Buffer.from(dataSourceStr, "utf-8");

        console.log("dataSourceStr = ", dataSourceStr);
        console.log("dataSourceStr length = ", dataSourceStr.length);
        

        console.log("================== 1. AES-GCM encrypt ==================");
        const hdNodeNew1 = hdNode.derivePath(newBasePath + "/" + id1);
        const walletTmp1 = new ethers.Wallet(hdNodeNew1.privateKey);
        const publicKey1 = walletTmp1.publicKey;
        const privateKey1 = walletTmp1.privateKey;
        // console.log("publicKey1: ", publicKey1);
        console.log("aes id: ", id1);
        console.log("aes key: ", privateKey1);

        const firstKey = privateKey1.substring(2);
        const dataSourceBuffer = Buffer.from(dataSourceStr, "utf-8");
        let firstAesEncBytes = await aesEncryptBson(firstKey, dataSourceBuffer, id1);

        console.log("firstAesEncBytes base64: ", firstAesEncBytes.toString("base64"));
        console.log("firstAesEncBytes length: ", firstAesEncBytes.length);
        // console.log("firstAesEncBytes hex: ", firstAesEncBytes.toString("hex"));
        // const firstAesEncStrDecode = BSON.deserialize(firstAesEncBytes);
        // console.log(`aes ct hex: ` + firstAesEncStrDecode.ct.toString("hex"));
        // console.log(`aes iv hex: ` + firstAesEncStrDecode.iv.toString("hex"));
        // console.log(`aes tg hex: ` + firstAesEncStrDecode.tg.toString("hex"));

        // google chacha20
        console.log("================== 2. ChaCha20-Poly1305 encrypt ==================");
        const id2 = 3;
        const hdNodeNew2 = hdNode.derivePath(newBasePath + "/" + id2);
        const walletTmp2 = new ethers.Wallet(hdNodeNew2.privateKey);
        const publicKey2 = walletTmp2.publicKey;
        const privateKey2 = walletTmp2.privateKey;
        // console.log("publicKey2: ", publicKey2);
        console.log("chacha20 id: ", id2);
        console.log("chacha20 key: ", privateKey2);

        const secondKey = privateKey2.substring(2);
        let secondChacha20EncBytes = await chacha20poly1305EncryptBson(secondKey, firstAesEncBytes, id2);
        console.log(`secondChacha20EncBytes base64: `, secondChacha20EncBytes.toString("base64"));
        console.log(`secondChacha20EncBytes length(final length):`, secondChacha20EncBytes.length);


        const secondChacha20EncStrDecode = BSON.deserialize(secondChacha20EncBytes);
        // console.log("secondChacha20EncStrDecode: ", secondChacha20EncStrDecode);
        // console.log(`secondChacha20EncStrDecode ct: `, secondChacha20EncStrDecode.ct);
        // console.log(`secondChacha20EncStrDecode iv: `, secondChacha20EncStrDecode.iv.value().toString("hex"));


        console.log("================== 3. ChaCha20-Poly1305 decrypt ==================");

        const chacha20Id = secondChacha20EncStrDecode.id;
        console.log(`chacha20Id = ${chacha20Id}`);
        const hdNodeNew3 = hdNode.derivePath(newBasePath + "/" + chacha20Id);
        const walletTmp3 = new ethers.Wallet(hdNodeNew3.privateKey);
        const publicKey3 = walletTmp3.publicKey;
        const privateKey3 = walletTmp3.privateKey;
        const privateKeyHex3 = privateKey3.substring(2);
        console.log(`chacha20 key = ${privateKeyHex3}`);

        let chacha20DecryptBsonBytes = await chacha20poly1305DecryptBson(privateKeyHex3, secondChacha20EncBytes);
        
        console.log(`chacha20DecryptBsonBytes length:`, chacha20DecryptBsonBytes.length);
        


        console.log("================== 4. AES-GCM decrypt ==================");
        const chacha20DecryptBsonBytesDecode = BSON.deserialize(chacha20DecryptBsonBytes);

        const aesId = chacha20DecryptBsonBytesDecode.id;
        console.log(`aesId = ${aesId}`);
        const hdNodeNew4 = hdNode.derivePath(newBasePath + "/" + aesId);
        const walletTmp4 = new ethers.Wallet(hdNodeNew4.privateKey);
        const publicKey4 = walletTmp4.publicKey;
        const privateKey4 = walletTmp4.privateKey;
        const privateKeyHex4 = privateKey4.substring(2);
        console.log(`aes key = ${privateKeyHex4}`);

        let aesDecryptBinary = await aesDecryptBson(privateKeyHex4, chacha20DecryptBsonBytes);
        console.log(`aesDecryptBinary length:`, aesDecryptBinary.length);
        const rawDataAfter = aesDecryptBinary.toString("utf-8");
        console.log(`raw data:`, rawDataAfter);
        console.log(`raw data length:`, rawDataAfter.length);

        
        console.log(`================== nodejs bson encrypt/decrypt end  ==================`);
        console.log();

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
