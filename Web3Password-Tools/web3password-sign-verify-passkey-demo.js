/*
Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/


const { ethers, utils } = require("ethers");

// uuidv4();
const { v4: uuidv4 } = require('uuid');
// const { sha256 } = require("eccrypto-js");

const crypto = require('crypto');


// https://github.com/mongodb/js-bson#bugs--feature-requests
const { BSON, EJSON, ObjectId, Binary } = require('bson');

const main = async () => {
    try {
        console.log("-----------------------sign-------------------------");
        // new mnemonic phrase
        let mnemonic = utils.entropyToMnemonic(utils.randomBytes(20)); // 15
        console.log("mnemonic: ", mnemonic);

        const hdNode = utils.HDNode.fromMnemonic(mnemonic);

        let basePath = "m/44'/60'/0'/0";
        let addressIndex = 0;
        let hdNodeNew = hdNode.derivePath(basePath + "/" + addressIndex);
        let walletNew = new ethers.Wallet(hdNodeNew.privateKey);
        const addr = walletNew.address.toLowerCase();
        console.log(`privateKey: ${hdNodeNew.privateKey}`);
        console.log(`publicKey: ${walletNew.publicKey}`);
        console.log(`addr: ${addr}`);

        const signingKey = new ethers.utils.SigningKey(hdNodeNew.privateKey);
        
        
        const appendDataStr = "web3password-append-data-str-test-from-nodejs-20230916";
        const appendDataStrHash = crypto.createHash("sha256").update(appendDataStr).digest("hex");;
        // console.log(`appendDataStrHash: ${appendDataStrHash}`);
        const w3pApiRequestParamsObject = {
            "addr": addr,
            "timestamp": Math.floor(Date.now() / 1000),
            "op_timestamp": Math.floor(Date.now() / 1000),
            // "id": Math.floor(Date.now()),
            "id": uuidv4(),
            "credential": "password-data-from-stamhe-" + Date.now() + uuidv4(),
            "nonce": "random-string-from-stamhe-test-" + Date.now() + uuidv4(),
            "hash": appendDataStrHash,
        };


        // https://stackoverflow.com/questions/61682191/go-ethereum-sign-provides-different-signature-than-nodejs-ethers
        let w3pApiRequestParamsStr = JSON.stringify(w3pApiRequestParamsObject);
        console.log(`w3pApiRequestParamsStr: ${w3pApiRequestParamsStr}`);

        const msgHash = ethers.utils.id(w3pApiRequestParamsStr);
        const signatureDigest = signingKey.signDigest(msgHash);
        let signature = ethers.utils.joinSignature(signatureDigest);


        const w3pApiRequestObject = {
            "signature": signature,
            "params": w3pApiRequestParamsStr,
            "data": Buffer.from(appendDataStr, "utf-8"),
        };

        const w3pApiRequestBytes = BSON.serialize(w3pApiRequestObject);
        const w3pApiRequestStrBase64 = w3pApiRequestBytes.toString("base64");
        console.log(`REQUEST Base64 Str(L2 TX): ${w3pApiRequestStrBase64}`);

        console.log(`signature: ${signature}`);
        const recoveryAddr = ethers.utils.recoverAddress(msgHash, signature).toLowerCase();
        console.log(`expect addr: ${addr}, recovery addr: ${recoveryAddr}`);
    } catch (err) {
        console.log(`error: ${err}`);
    }
};

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
