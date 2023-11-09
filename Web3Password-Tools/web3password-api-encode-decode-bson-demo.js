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

const {Web3PasswordSleep2, aesEncryptBson, aesDecryptBson, chacha20poly1305EncryptBson, chacha20poly1305DecryptBson, Web3PasswordRequestEncodeBsonApi, Web3PasswordRequestDecodeBsonApi, } = require("./web3password-lib");

const Web3PasswordMnemonicTest = `science hundred humor hat jelly kangaroo receive drum buzz elite gym witness tuna shrug enlist`;


const hdNode = ethers.utils.HDNode.fromMnemonic(Web3PasswordMnemonicTest);

let basePath = "m/44'/60'/0'/0";
let addressIndex = 0; // primary address/primary key
let hdNodeNew = hdNode.derivePath(basePath + "/" + addressIndex);
const wallet0 = new ethers.Wallet(hdNodeNew.privateKey);

const main = async () => {
    try {
        let address0 = await wallet0.getAddress();
        const publicKey0 = wallet0.publicKey;
        const privateKey0 = wallet0.privateKey;
        console.log("address0: ", address0);
        console.log("publicKey0: ", publicKey0);
        console.log("privateKey0: ", privateKey0);

        console.log(`----------------------------- web3password api decode start-----------------------------------`);
        console.log(`/web3password/addCredential example`)

        const w3pAddCredentialRequestBase64Str = "MDEAAAMeHgMAAAVkYXRhAEQBAAAARAEAABBjbQAAAAAAAmNuAAMAAABjcAAFY3QA7QAAAABkU313kMSWzcRXQwezoX7oq6TZcZXhVGx8nsxVqhP/5T4FOf4kC+VOPkECinnrh9CPKs6YFKm0W8KEnwBr1V1JYQVLNhDtPSt0WGIGFeOH5QBIxTvLQTAgr3bcbf2m7sDooWsXAKy3DOFg9J84PAGz9dbbSE42vZPyofYzfMByn/IXEryW78c0iwrGz9KOQjDisaEIgYuGdocTDlMVfTXep+bVn4BTq4rVK3sNQCXkC8Bpb1rQS7HoJHpxHNYZ8ePstEU6ZdFPGyXeUlDED0T4yCtQwdJ8B/txGREoBrVORqDaSDTEHT+6X4W4/UcQaWQA4QMAAAVpdgAMAAAAADtmSgFk2OUZlHleBgV0ZwAQAAAAAMf/8/EWajo1Tpck6ctsQgIAAnBhcmFtcwAqAQAAeyJhZGRyIjoiMHhlNGZjYWY2N2YyZjFkMTljOWEyMmVlOWNlZWM5ZGExYTQ2NjQ1MWU2IiwiY3JlZGVudGlhbCI6bnVsbCwiZmxvd19pZCI6MCwiaGFzaCI6ImJhNWI1Yzk3MDFjYzNlZGM0YzYwZTNiNDczNWMxNDdjZDExNTdhYjE2ZmQwMTdhMjY2OGM0MDE1MTBkNjU4MzIiLCJpZCI6ImM0MWY0MmRhLTVhNDEtNDYyYi1hZTM2LTJiNzM3MGVlYmM0OSIsIm5vbmNlIjoiN2MzNWViZjEtZDUwOS00YjU4LTliYzUtYTA4M2JhOWI3NzUyIiwib3BfdGltZXN0YW1wIjoxNjk5NTA1NzI5LCJ0aW1lc3RhbXAiOjE2OTk1MDU3Mjl9AAJzaWduYXR1cmUAhQAAADB4NzFmOTBlMzAyNmUwMDUwZTFmZjdjNTI3ZmZlMzA4YmFkMDVmMzgwN2QzOWUzOWYxODllNjIwZDU2NGMzOTVjMTdmMDBjMmUxMzQ2ODllMTVjZjIyNWFjZTZlMTlmNmYzZmMwMTA3YTRlMzM3YzI3Y2M0NTQ4YjljYjQyYTQ3YzUxYgAA";
        const w3pAddCredentialRequestBytes = Buffer.from(w3pAddCredentialRequestBase64Str, "base64");

        const w3pAddCredentialRequestObject = await Web3PasswordRequestDecodeBsonApi(w3pAddCredentialRequestBytes);

        console.log("signature length: ", w3pAddCredentialRequestObject.signature.length);
        console.log("signature: ", w3pAddCredentialRequestObject.signature);
        console.log("params length: ", w3pAddCredentialRequestObject.params.length);
        console.log("params: ", w3pAddCredentialRequestObject.params);
        console.log("append length: ", w3pAddCredentialRequestObject.data.length);
        console.log("append Hex: ", w3pAddCredentialRequestObject.data.toString("hex"));

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

        console.log(`----------------------------- web3password api decode end-----------------------------------`);
        
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
