/*
Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

const Tail = require('tail').Tail;  
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

if (process.argv.length != 4) {
  console.log("Usage: node web3password-api-audit.js your-mnemonic-phrase Satis_Logfile");
  exit(1);
}


const Web3PasswordMnemonic = process.argv[2];
const SatisLogfile = process.argv[3];

if (SatisLogfile != "") {
  console.log("SatisLogfile: " + SatisLogfile);

  // Creating a Tail instance and listening for file change events
  const tail = new Tail(SatisLogfile);  
  tail.on('line', (content) => {
    content = content.toString();  
    var jsonData = JSON.parse(content); 
    if (jsonData.msg.includes("getLatestBlockTimestamp")) {
      ;
    } else if(jsonData.level==='INFO' && 
      (jsonData.msg.includes('addCredential') || jsonData.msg.includes('batchAddCredential') || 
      jsonData.msg.includes('deleteCredential') || jsonData.msg.includes('batchDeleteCredential'))){
      W3PDecryptRecord(jsonData);
    } else {
      W3POtherAPI(jsonData);
    }
  });
} else { 
  console.log("Usage: node web3password-api-audit.js your-mnemonic-phrase Satis_Logfile");
  exit(1);
}

const hdNode = ethers.utils.HDNode.fromMnemonic(Web3PasswordMnemonic);
let basePath = "m/44'/60'/0'/0";
let addressIndex = 0; // primary address/primary key
let hdNodeNew = hdNode.derivePath(basePath + "/" + addressIndex);
const wallet0 = new ethers.Wallet(hdNodeNew.privateKey);

const W3PDecryptRecord = async (jsonData) => {
  try {
    const w3p_method = jsonData.msg;
    console.log(`----------------------------- web3password api ${w3p_method} decode start-----------------------------------`);
    const audit_log = jsonData.audit_log;
    let address0 = await wallet0.getAddress();
    console.log(`UserID: ${address0}, method: ${w3p_method}`);

    const w3pRequestBase64Str = audit_log
    const w3pRequestBytes = Buffer.from(w3pRequestBase64Str, "base64");

    const w3pRequestObject = await Web3PasswordRequestDecodeBsonApi(w3pRequestBytes);
    const params = JSON.parse(w3pRequestObject.params);  
    if (params.addr.toLowerCase() != address0.toLowerCase()) {
      console.log(`not your UserID: ${params.addr}`);
      return;
    }

    // console.log("signature length: ", w3pRequestObject.signature.length);
    console.log("signature: ", w3pRequestObject.signature);
    // console.log("params length: ", w3pRequestObject.params.length);
    console.log("params: ", w3pRequestObject.params);
    // console.log("append length: ", w3pRequestObject.data.length);
    // console.log("append Hex: ", w3pRequestObject.data.toString("hex"));

    console.log("----------------------------- decrypt start -----------------------------");
    console.log("---------- first chacha20 decrypt --------------");
    const chacha20BsonBytes = w3pRequestObject.data;
    const chacha20BsonObject = BSON.deserialize(chacha20BsonBytes)
    let chacha20AddressIndex = chacha20BsonObject.id
    let hdNodeNew1 = hdNode.derivePath(basePath + "/" + chacha20AddressIndex);
    const wallet1 = new ethers.Wallet(hdNodeNew1.privateKey);
    const publicKey1 = wallet1.publicKey;
    const privateKey1 = wallet1.privateKey;
    const chacha20Key = privateKey1.substring(2);
    console.log("Chacha20Poly1305 algoSimpleName: ", chacha20BsonObject.cn);
    console.log("Chacha20Poly1305 id: ", chacha20AddressIndex);
    console.log("Chacha20Poly1305 key: ", chacha20Key);

    const aesBsonBytes = await chacha20poly1305DecryptBson(chacha20Key, chacha20BsonBytes);
    console.log("---------- second aes decrypt ----------------");
    const aesBsonObject = BSON.deserialize(aesBsonBytes);
    let aesAddressIndex = aesBsonObject.id
    let hdNodeNew2 = hdNode.derivePath(basePath + "/" + aesAddressIndex);
    const wallet2 = new ethers.Wallet(hdNodeNew2.privateKey);
    const publicKey2 = wallet2.publicKey;
    const privateKey2 = wallet2.privateKey;
    const aesKey = privateKey2.substring(2);
    console.log("AES-256-GCM algoSimpleName: ", aesBsonObject.cn);
    console.log("AES-256-GCM id: ", aesAddressIndex);
    console.log("AES-256-GCM key: ", aesKey);
    const rawCredentialBytes = await aesDecryptBson(aesKey, aesBsonBytes);
    console.log(`rawCredentialBytes Length: `, rawCredentialBytes.length);
    console.log(`rawCredentialBytes to Str: `, rawCredentialBytes.toString("utf-8"));
    console.log("----------------------------- decrypt end -----------------------------");

    console.log(`----------------------------- web3password api ${w3p_method} decode end-----------------------------------`);
  } catch (err) {
    console.log(err.message);
  }
};

const W3POtherAPI = async (jsonData) => {
  try {
    const w3p_method = jsonData.msg;
    console.log(`----------------------------- web3password api ${w3p_method} decode start-----------------------------------`);
    const audit_log = jsonData.audit_log;
    let address0 = await wallet0.getAddress();
    console.log(`UserID: ${address0}, method: ${w3p_method}`);
    // console.log(jsonData);

    const w3pRequestBase64Str = audit_log
    const w3pRequestBytes = Buffer.from(w3pRequestBase64Str, "base64");

    const w3pRequestObject = await Web3PasswordRequestDecodeBsonApi(w3pRequestBytes);
    const params = JSON.parse(w3pRequestObject.params);  
    if (params.addr.toLowerCase() != address0.toLowerCase()) {
      console.log(`not your UserID: ${params.addr}`);
      return;
    }
    
    // console.log("signature length: ", w3pRequestObject.signature.length);
    console.log("signature: ", w3pRequestObject.signature);
    // console.log("params length: ", w3pRequestObject.params.length);
    console.log("params: ", w3pRequestObject.params);
    
    const paramsObj = JSON.parse(w3pRequestObject.params);
    if (paramsObj.hash != undefined && paramsObj.hash != null && paramsObj.hash != "" && w3pRequestObject.data.length > 0) {
      console.log("append length: ", w3pRequestObject.data.length);
      console.log("append data: ", BSON.deserialize(w3pRequestObject.data));
    }

    console.log(`----------------------------- web3password api ${w3p_method} decode end-----------------------------------`);
  } catch (err) {
    console.log(err.message);
  }
}