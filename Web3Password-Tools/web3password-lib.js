/*
Copyright (C) 2023 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved 

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

const { ethers } = require("ethers");

const crypto = require('crypto')
const buffer = require('buffer');
const {gzip, ungzip} = require('node-gzip');
// const secp256k1 = require("secp256k1");
// uuidv4();
const { v4: uuidv4 } = require('uuid');
const { BSON, EJSON, ObjectId, Binary } = require('bson');
const { zlib } = require("fflate");


async function aesEncryptBson (key, dataBinary, id) {
    const ALGO = 'aes-256-gcm';
    const algoSimpleName = "ag";
    const ivBuffer = crypto.randomBytes(16);
    const keyBuffer = Buffer.from(key, "hex");
    let dataBuffer = Buffer.from(dataBinary, "binary");
    let compressMode = 0; // 0 => no compress, 1 => gzip
    const dataLength = dataBuffer.length;
    if (dataLength < 2 * 1024 * 1024) {
        compressMode = 1;
    } else {
        const testLength = 1 * 1024 * 1024;
        const testBuffer = dataBuffer.subarray(0, testLength);
        const testCmBuffer = await gzip(testBuffer, { level: 1, });

        if (testCmBuffer.length / testLength <= 0.7) {
            compressMode = 1;
        }

        console.log("ratio: ", testCmBuffer.length / testLength);
    }

    if (compressMode == 1) {
        // gzip first
        dataBuffer = await gzip(dataBuffer, {
            level: 1,
        });
        // console.log(`first gzip length: `, dataBuffer.length);
    }

    const cipher = crypto.createCipheriv(ALGO, keyBuffer, ivBuffer, {authTagLength: 16,});
    // cipher.update(data[,input_encoding][,output_encoding])
    // input could be: 'utf8', 'ascii', 'binary', output could be: 'binary', 'base64', 'hex')
    
    let ciphertext1 = cipher.update(dataBuffer, 'binary', "binary");
    let ciphertext2 = cipher.final("binary");
    let ciphertextTmp = [Buffer.from(ciphertext1, "binary"), Buffer.from(ciphertext2, "binary")];
    let ciphertext = Buffer.concat(ciphertextTmp);
    // console.log(`ivBuffer length: `, ivBuffer.length);
    // console.log(`cipher.getAuthTag() length: `, cipher.getAuthTag().length);

    const finalObj = {
        "cn": algoSimpleName,
        "ct": ciphertext,
        "iv": ivBuffer,
        "tg": cipher.getAuthTag(),
        "id": id * 1,
        "cm": compressMode,    // is compression or compress mode ?
    };
    
    return BSON.serialize(finalObj);
};



async function aesDecryptBson(key, finalBuffer) {
    const ALGO = 'aes-256-gcm';
    const algoSimpleName = "ag";
    const keyBuffer = Buffer.from(key, "hex");
    
    const objTmp = BSON.deserialize(finalBuffer)

    const ivBuffer = Buffer.from(objTmp.iv.value(), "binary");
    const tagBuffer = Buffer.from(objTmp.tg.value(), "binary");
    const ciphertextBuffer = Buffer.from(objTmp.ct.value(), "binary");
    const cm = objTmp.cm;

    const cipher = crypto.createDecipheriv(ALGO, keyBuffer, ivBuffer, { authTagLength: 16, });
    cipher.setAuthTag(tagBuffer);
    let bodyBinary = cipher.update(ciphertextBuffer, "binary", "binary");
    let finalBinary = cipher.final("binary");

    const textBufferCompressed = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);
    if (cm == 1) {
        const textBuffer = await ungzip(textBufferCompressed);
        return textBuffer;
    } else {
        return textBufferCompressed;
    }
}



async function chacha20poly1305EncryptBson(key, dataBinary, id) {
    const ALGO = 'chacha20-poly1305';
    const algoSimpleName = "cp";
    const keyBuffer = Buffer.from(key, "hex");
    const ivBuffer = crypto.randomBytes(12);    // must be 12 bytes for chacha20
    // const dataBuffer = await gzip(data);     // no compress
    const compressMode = 0; // 0 => no compression
    const dataBuffer = Buffer.from(dataBinary, "binary");

    // console.log(`second gzip length: `, dataBuffer.length);

    // cipher.update(data[,input_encoding][,output_encoding])
    // input could be: 'utf8', 'ascii', 'binary', output could be: 'binary', 'base64', 'hex')
    let cipher = crypto.createCipheriv(ALGO, keyBuffer, ivBuffer, { authTagLength: 16 });
    

    let ciphertext1 = cipher.update(dataBuffer, 'binary', "binary");
    let ciphertext2 = cipher.final("binary");
    
    // let ciphertextTmp = [ciphertext1, ciphertext2];
    let ciphertextTmp = [Buffer.from(ciphertext1, "binary"), Buffer.from(ciphertext2, "binary")];
    let ciphertext = Buffer.concat(ciphertextTmp);

    const finalObj = {
        "cn": algoSimpleName,
        "ct": ciphertext,
        "iv": ivBuffer,
        "tg": cipher.getAuthTag(),
        "id": id * 1,
        "cm": compressMode,    // is compression or compress mode ?
    };

    return BSON.serialize(finalObj);
}


async function chacha20poly1305DecryptBson(key, finalBuffer) {
    const ALGO = 'chacha20-poly1305';
    const algoSimpleName = "cp";
    const keyBuffer = Buffer.from(key, "hex");

    const objTmp = BSON.deserialize(finalBuffer)

    const ivBuffer = Buffer.from(objTmp.iv.value(), "binary");
    const tagBuffer = Buffer.from(objTmp.tg.value(), "binary");
    const ciphertextBuffer = Buffer.from(objTmp.ct.value(), "binary");
    // console.log(`decrypt iv hex: `, ivBuffer.toString("hex"));

    // cipher.update(data[,input_encoding][,output_encoding])
    // input could be: 'utf8', 'ascii', 'binary', output could be: 'binary', 'base64', 'hex')
    let cipher = crypto.createDecipheriv(ALGO, keyBuffer, ivBuffer, {authTagLength: 16});
    cipher.setAuthTag(tagBuffer);
    let bodyBinary = cipher.update(ciphertextBuffer, "binary", "binary");
    let finalBinary = cipher.final("binary");

    const textBufferCompressed = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);
    // const textBuffer = await ungzip(textBufferCompressed);
    return textBufferCompressed;
}



// ECDH-Sha256
const ETH_SECP256K1N = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = Buffer.alloc(32, 0);

function isValidPrivateKey(privateKey) {
  if ((Buffer.isBuffer(privateKey) && privateKey.length === 32) == false)
  {
    return false;
  }
  return privateKey.compare(ZERO32) > 0 && // > 0
  privateKey.compare(ETH_SECP256K1N) < 0; // < G
}



// https://github.com/crypto-browserify/createECDH
// https://github.com/indutny/elliptic
// https://www.npmjs.com/package/secp256k1
// https://www.npmjs.com/package/eccrypto
async function publicKeyEncryptAESBson(publicKey, data, id) {
    const curveName = "secp256k1";
    const publicKeyBuffer = Buffer.from(publicKey, "hex");
    const keyLengthBytes = 32;

    const mnemonic = ethers.utils.entropyToMnemonic(ethers.utils.randomBytes(32));
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);
    let basePath = "m/44'/60'/0'/0/0";
    let hdNodeNew = hdNode.derivePath(basePath);
    let walletNew = new ethers.Wallet(hdNodeNew);
    let ephemPrivateKeyBuffer = Buffer.from(walletNew.privateKey.substring(2), "hex")
    // console.log("0 ephemPrivateKeyBuffer = ", ephemPrivateKeyBuffer.toString("hex"));
    // console.log("0 ephemPrivateKeyBuffer length = ", ephemPrivateKeyBuffer.length);


    // Compute the public key for a given private key.
    // See https://github.com/wanderer/secp256k1-node/issues/46, ephemPublicKeyBuffer = > false , uncompressed...
    const ephemPublicKeyUint8Array = secp256k1.publicKeyCreate(ephemPrivateKeyBuffer, false);
    const ephemPublicKeyBuffer = Buffer.from(ephemPublicKeyUint8Array.buffer);

    var ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(ephemPrivateKeyBuffer);
    const XPositionKeyBuffer = ecdh.computeSecret(publicKeyBuffer);
    // console.log("1 XPositionKeyBuffer = ", XPositionKeyBuffer.toString("hex"));
    // console.log("1 XPositionKeyBuffer length = ", XPositionKeyBuffer.length);

    const XPositionKeyHashBuffer = crypto.createHash("sha512").update(XPositionKeyBuffer).digest();
    const encryptionKeyBuffer = XPositionKeyHashBuffer.subarray(0, 32);
    const macKeyBuffer = XPositionKeyHashBuffer.subarray(32);


    // console.log("1 XPositionKeyHashBuffer = ", XPositionKeyHashBuffer.toString("hex"));
    // console.log("1 XPositionKeyHashBuffer length = ", XPositionKeyHashBuffer.length);

    // aes-256-gcm
    const ALGO = 'aes-256-gcm';
    const algoSimpleName = "ag";
    const ivBuffer = crypto.randomBytes(16);

    const dataBuffer = await gzip(data);
    const compressMode = 1; // 1 => gzip

    const cipher = crypto.createCipheriv(ALGO, encryptionKeyBuffer, ivBuffer, {authTagLength: 16,});

    // cipher.update(data[,input_encoding][,output_encoding])
    // input could be: 'utf8', 'ascii', 'binary', output could be: 'binary', 'base64', 'hex')
    let bodyBinary = cipher.update(dataBuffer, 'binary', "binary");
    let finalBinary = cipher.final("binary");

    const ciphertextBuffer = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);


    // compute hmac hash
    var dataToMacBuffer = Buffer.concat([ivBuffer, ephemPublicKeyBuffer, ciphertextBuffer]);
    const  macBuffer  = crypto.createHmac("sha256", macKeyBuffer).update(dataToMacBuffer).digest()

    // console.log("2 ephemPrivateKeyBuffer = ", ephemPrivateKeyBuffer.toString("hex"));
    // console.log("2 ephemPrivateKeyBuffer length = ", ephemPrivateKeyBuffer.length);

    // console.log("3 ephemPublicKeyBuffer = ", ephemPublicKeyBuffer.toString("hex"));
    // console.log("3 ephemPublicKeyBuffer length = ", ephemPublicKeyBuffer.length);
    const finalObj = {
        "id": id * 1,
        "cm": compressMode,    // is compression or compress mode ?
        "cn": algoSimpleName,
        "ct": ciphertextBuffer,
        "iv": ivBuffer,
        "tg": cipher.getAuthTag(),
        "ep": ephemPublicKeyBuffer,
        "mc": macBuffer,
    };

    return BSON.serialize(finalObj);
}


async function privateKeyDecryptAESBson(privateKey, ct, iv, tg, ep, mc) {
    const curveName = "secp256k1";
    const privateKeyBuffer = Buffer.from(privateKey, "hex");

    
    const ephemPublicKeyBuffer = Buffer.from(ep, "binary");
    const ivBuffer = Buffer.from(iv, "binary");
    const ciphertextBuffer = Buffer.from(ct, "binary");
    const authTagBuffer = Buffer.from(tg, "binary");
    const macBuffer = Buffer.from(mc, "binary");

    // console.log();
    // console.log("privateKeyBuffer = ", privateKeyBuffer.toString("hex"));
    // console.log("ephemPublicKeyBuffer = ", ephemPublicKeyBuffer.toString("hex"));
    // console.log("ephemPublicKeyBuffer length = ", ephemPublicKeyBuffer.length);

    var ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privateKeyBuffer);
    const XPositionKeyBuffer = ecdh.computeSecret(ephemPublicKeyBuffer);
    // console.log("XPositionKeyBuffer = ", XPositionKeyBuffer.toString("hex"));
    // console.log("XPositionKeyBuffer length = ", XPositionKeyBuffer.length);

    const XPositionKeyHashBuffer = crypto.createHash("sha512").update(XPositionKeyBuffer).digest();
    const encryptionKeyBuffer = XPositionKeyHashBuffer.subarray(0, 32);
    const macKeyBuffer = XPositionKeyHashBuffer.subarray(32);


    // console.log("XPositionKeyHashBuffer = ", XPositionKeyHashBuffer.toString("hex"));
    // console.log("XPositionKeyHashBuffer length = ", XPositionKeyHashBuffer.length);

    // console.log("encryptionKeyBuffer = ", encryptionKeyBuffer.toString("hex"));
    // console.log("encryptionKeyBuffer length = ", encryptionKeyBuffer.length);

    // compute hmac hash
    var dataToMacBuffer = Buffer.concat([ivBuffer, ephemPublicKeyBuffer, ciphertextBuffer]);
    const  newMacBuffer  = crypto.createHmac("sha256", macKeyBuffer).update(dataToMacBuffer).digest()
    // console.log("macKeyBuffer = ", macKeyBuffer.toString("hex"));
    // console.log("dataToMacBuffer = ", dataToMacBuffer.toString("hex"));
    // console.log("dataToMacBuffer length = ", dataToMacBuffer.length);
    // console.log("newMacBuffer = ", newMacBuffer.toString("hex"));

    // if (macBuffer.equals(newMacBuffer) != true) {
    //     return null;
    // }



    // aes-256-gcm
    const ALGO = 'aes-256-gcm';
    const cipher = crypto.createDecipheriv(ALGO, encryptionKeyBuffer, ivBuffer, { authTagLength: 16, });
    cipher.setAuthTag(authTagBuffer);
    let bodyBinary = cipher.update(ciphertextBuffer, "binary", "binary");
    let finalBinary = cipher.final("binary");

    const textBufferCompressed = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);
    const textBuffer = await ungzip(textBufferCompressed);
    return textBuffer;
}



async function publicKeyEncryptCHACHA20Bson(publicKey, dataBinary, id) {
    const curveName = "secp256k1";
    const publicKeyBuffer = Buffer.from(publicKey, "hex");
    const keyLengthBytes = 32;

    const mnemonic = ethers.utils.entropyToMnemonic(ethers.utils.randomBytes(32));
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);
    let basePath = "m/44'/60'/0'/0/0";
    let hdNodeNew = hdNode.derivePath(basePath);
    let walletNew = new ethers.Wallet(hdNodeNew);
    let ephemPrivateKeyBuffer = Buffer.from(walletNew.privateKey.substring(2), "hex")

    // console.log();
    // console.log("0 ephemPrivateKeyBuffer = ", ephemPrivateKeyBuffer.toString("hex"));
    // console.log("0 ephemPrivateKeyBuffer length = ", ephemPrivateKeyBuffer.length);


    // Compute the public key for a given private key.
    // See https://github.com/wanderer/secp256k1-node/issues/46, ephemPublicKeyBuffer = > false , uncompressed...
    const ephemPublicKeyUint8Array = secp256k1.publicKeyCreate(ephemPrivateKeyBuffer, false);
    const ephemPublicKeyBuffer = Buffer.from(ephemPublicKeyUint8Array.buffer);

    var ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(ephemPrivateKeyBuffer);
    const XPositionKeyBuffer = ecdh.computeSecret(publicKeyBuffer);
    // console.log("1 XPositionKeyBuffer = ", XPositionKeyBuffer.toString("hex"));
    // console.log("1 XPositionKeyBuffer length = ", XPositionKeyBuffer.length);

    const XPositionKeyHashBuffer = crypto.createHash("sha512").update(XPositionKeyBuffer).digest();
    const encryptionKeyBuffer = XPositionKeyHashBuffer.subarray(0, 32);
    const macKeyBuffer = XPositionKeyHashBuffer.subarray(32);


    // console.log("1 XPositionKeyHashBuffer = ", XPositionKeyHashBuffer.toString("hex"));
    // console.log("1 XPositionKeyHashBuffer length = ", XPositionKeyHashBuffer.length);

    // chacha20-poly1305
    const ALGO = 'chacha20-poly1305';
    const algoSimpleName = "cp";
    const ivBuffer = crypto.randomBytes(12);    // must be 12 bytes for chacha20

    // const dataBuffer = await gzip(data);
    const dataBuffer = Buffer.from(dataBinary, "binary");

    const cipher = crypto.createCipheriv(ALGO, encryptionKeyBuffer, ivBuffer, {authTagLength: 16,});

    // cipher.update(data[,input_encoding][,output_encoding])
    // input could be: 'utf8', 'ascii', 'binary', output could be: 'binary', 'base64', 'hex')
    let bodyBinary = cipher.update(dataBuffer, 'binary', "binary");
    let finalBinary = cipher.final("binary");

    const ciphertextBuffer = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);
    // compute hmac hash
    var dataToMacBuffer = Buffer.concat([ivBuffer, ephemPublicKeyBuffer, Buffer.from(ciphertextBuffer, "binary")]);
    const  macBuffer  = crypto.createHmac("sha256", macKeyBuffer).update(dataToMacBuffer).digest()

    // console.log("2 ephemPrivateKeyBuffer = ", ephemPrivateKeyBuffer.toString("hex"));
    // console.log("2 ephemPrivateKeyBuffer length = ", ephemPrivateKeyBuffer.length);

    // console.log("3 ephemPublicKeyBuffer = ", ephemPublicKeyBuffer.toString("hex"));
    // console.log("3 ephemPublicKeyBuffer length = ", ephemPublicKeyBuffer.length);
    const dataEnc = {
        "id": id,
        "cm": 0,    // chacha20 => no compression
        "cn": algoSimpleName,
        "ct": ciphertextBuffer,
        "iv": ivBuffer,
        "tg": cipher.getAuthTag(),
        "ep": ephemPublicKeyBuffer,
        "mc": macBuffer,
    };

    return BSON.serialize(dataEnc);
}



async function privateKeyDecryptCHACHA20Bson(privateKey, ct, iv, tg, ep, mc) {
    const curveName = "secp256k1";
    const privateKeyBuffer = Buffer.from(privateKey, "hex");
    const ephemPublicKeyBuffer = Buffer.from(ep, "binary");
    const ivBuffer = Buffer.from(iv, "binary");
    const ciphertextBuffer = Buffer.from(ct, "binary");
    const authTagBuffer = Buffer.from(tg, "binary");
    const macBuffer = Buffer.from(mc, "binary");

    // console.log();
    // console.log("privateKeyBuffer = ", privateKeyBuffer.toString("hex"));
    // console.log("ephemPublicKeyBuffer = ", ephemPublicKeyBuffer.toString("hex"));
    // console.log("ephemPublicKeyBuffer length = ", ephemPublicKeyBuffer.length);

    var ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privateKeyBuffer);
    const XPositionKeyBuffer = ecdh.computeSecret(ephemPublicKeyBuffer);
    // console.log("XPositionKeyBuffer = ", XPositionKeyBuffer.toString("hex"));
    // console.log("XPositionKeyBuffer length = ", XPositionKeyBuffer.length);

    const XPositionKeyHashBuffer = crypto.createHash("sha512").update(XPositionKeyBuffer).digest();
    const encryptionKeyBuffer = XPositionKeyHashBuffer.subarray(0, 32);
    const macKeyBuffer = XPositionKeyHashBuffer.subarray(32);


    // console.log("XPositionKeyHashBuffer = ", XPositionKeyHashBuffer.toString("hex"));
    // console.log("XPositionKeyHashBuffer length = ", XPositionKeyHashBuffer.length);

    // console.log("encryptionKeyBuffer = ", encryptionKeyBuffer.toString("hex"));
    // console.log("encryptionKeyBuffer length = ", encryptionKeyBuffer.length);

    // compute hmac hash
    var dataToMacBuffer = Buffer.concat([ivBuffer, ephemPublicKeyBuffer, ciphertextBuffer]);
    const  newMacBuffer  = crypto.createHmac("sha256", macKeyBuffer).update(dataToMacBuffer).digest()
    // console.log("macKeyBuffer = ", macKeyBuffer.toString("hex"));
    // console.log("dataToMacBuffer = ", dataToMacBuffer.toString("hex"));
    // console.log("dataToMacBuffer length = ", dataToMacBuffer.length);
    // console.log("newMacBuffer = ", newMacBuffer.toString("hex"));

    // if (macBuffer.equals(newMacBuffer) != true) {
    //     return null;
    // }



    // chacha20-poly1305
    const ALGO = 'chacha20-poly1305';
    const cipher = crypto.createDecipheriv(ALGO, encryptionKeyBuffer, ivBuffer, { authTagLength: 16, });
    cipher.setAuthTag(authTagBuffer);
    let bodyBinary = cipher.update(ciphertextBuffer, "binary", "binary");
    let finalBinary = cipher.final("binary");

    const textBufferCompressed = Buffer.concat([Buffer.from(bodyBinary, "binary"), Buffer.from(finalBinary, "binary")]);
    // const textBuffer = await ungzip(textBufferCompressed);
    return textBufferCompressed;
}




async function Web3PasswordHexPaddingZero(dataHex, dataHexNeedLength) {
    let finalHex = dataHex;
    // js padding
    if (finalHex.length % 2 != 0) {
        finalHex = "0" + finalHex;
    }

    // js padding
    while (finalHex.length < dataHexNeedLength) {
        finalHex = "0" + finalHex;
    }

    return finalHex;
}




///////////////////////

async function Web3PasswordRequestEncodeBsonApi(signatureStr, paramsStr, appendDataBufferFrom) {
    const appendDataBuffer = Buffer.from(appendDataBufferFrom, "binary");

    const dataObj = {
        "signature": signatureStr,
        "params": paramsStr,
        "data": appendDataBuffer,
    };

    const dataBuffer = BSON.serialize(dataObj);

    const dataLength = dataBuffer.length;
    let dataLengthHex = dataLength.toString(16);  // 4 bytes
    dataLengthHex = await Web3PasswordHexPaddingZero(dataLengthHex, 8);

    const totalLength = 2 + 4 + dataLength;
    let finalBuffer = Buffer.alloc(totalLength);

    let start = 0;
    finalBuffer.write("01", start, 2, "utf-8"); // version

    start = start + 2;
    finalBuffer.write(dataLengthHex, start, 4, "hex"); // dataLengthHex

    start = start + 4;
    finalBuffer.write(dataBuffer.toString("hex"), start, dataLength, "hex"); // data buffer bytes
    
    return finalBuffer;
}


async function Web3PasswordRequestDecodeBsonApi(finalBuffer) {
    const finalObj = {
        version: "",
        signature: "",
        params: "",
        data: null,
    }

    let start = 0;
    let versionBufferHex = finalBuffer.toString("hex", start, start + 2); // version buffer bytes
    let versionStr = versionBufferHex.toString("utf-8");
    finalObj.version = versionStr;

    start = start + 2;
    let dataLengthHex = finalBuffer.toString("hex", start, start + 4); // dataLength
    let dataLength = parseInt(dataLengthHex, 16);
    let totalLength = dataLength + 6;
    if (totalLength != finalBuffer.length) {
        return null;
    }


    // appendData max 50 MiByte = 50 * 1024 * 1024
    if (dataLengthHex > 50 * 1024 * 1024 || dataLengthHex < 1) {
        return null;
    }

    start = start + 4;
    let dataBufferHex = finalBuffer.toString("hex", start, start + dataLength); // data buffer bytes
    let dataBuffer = Buffer.from(dataBufferHex, "hex");

    const dataObj = BSON.deserialize(dataBuffer);
    finalObj.signature = dataObj.signature;
    finalObj.params = dataObj.params;

    if (dataObj.hasOwnProperty("data") && dataObj.data !== null && dataObj.data !== undefined) {
        finalObj.data = dataObj.data.value();
    }


    return finalObj;
}


async function Web3PasswordResponseEncodeBsonApi(code, msg, rspBodyBufferFrom) {
    const rspBodyBuffer = Buffer.from(rspBodyBufferFrom, "binary");

    const dataObj = {
        "code": code,
        "msg": msg,
        "data": rspBodyBuffer,
    }


    const dataBuffer = BSON.serialize(dataObj);
    const dataLength = dataBuffer.length;
    let dataLengthHex = dataLength.toString(16);  // 4 bytes
    dataLengthHex = await Web3PasswordHexPaddingZero(dataLengthHex, 8);

    const totalLength = 2 + 4 + dataLength;
    let finalBuffer = Buffer.alloc(totalLength);

    let start = 0;
    finalBuffer.write("01", start, 2, "utf-8"); // version

    start = start + 2;
    finalBuffer.write(dataLengthHex, start, 4, "hex"); // dataLengthHex

    start = start + 4;
    finalBuffer.write(dataBuffer.toString("hex"), start, dataLength, "hex"); // data buffer bytes
    
    return finalBuffer;
}

async function Web3PasswordResponseDecodeBsonApi(finalBuffer) {
    const finalObj = {
        "versionStr": "",
        "code": "",
        "msg": "",
        "data": null,
    };

    let start = 0;
    let versionBufferHex = finalBuffer.toString("hex", start, start + 2); // version buffer bytes
    let versionStr = versionBufferHex.toString("utf-8");
    finalObj.versionStr = versionStr;

    start = start + 2;
    let dataLengthHex = finalBuffer.toString("hex", start, start + 4); // dataLength
    let dataLength = parseInt(dataLengthHex, 16);
    let totalLength = dataLength + 6;
    if (totalLength != finalBuffer.length) {
        return null;
    }


    // appendData max 50 MiByte = 50 * 1024 * 1024
    if (dataLength > 50 * 1024 * 1024 || dataLength < 1) {
        return null;
    }

    start = start + 4;
    let dataBufferHex = finalBuffer.toString("hex", start, start + dataLength); // data buffer bytes
    let dataBuffer = Buffer.from(dataBufferHex, "hex");

    const dataObj = BSON.deserialize(dataBuffer);
    finalObj.code = dataObj.code;
    finalObj.msg = dataObj.msg;
    finalObj.data = dataObj.data.value();


    return finalObj;
}




async function Web3PasswordSleep2(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function Web3passwordPBKDF2(password, saltHex, iter) {
    let isGet = false;
    let passwordHashDerivedKey;
    // password, salt, iter, keyLength, hash-method-name
    crypto.pbkdf2(password, saltHex, iter, 32, 'sha256', (err, derivedKey) => {
      if (err) throw err;
    //   console.log(derivedKey.toString('hex'), salt.toString('hex'));
        isGet = true;
        passwordHashDerivedKey = derivedKey.toString("base64");
        // passwordHashDerivedKey = derivedKey.toString("hex");
    });

    while (true) {
        await Web3PasswordSleep2(10);
        if (isGet === true) {
            break;
        }
    }

    return passwordHashDerivedKey;
}


module.exports = {
    aesEncryptBson: aesEncryptBson,
    aesDecryptBson: aesDecryptBson,
    chacha20poly1305EncryptBson: chacha20poly1305EncryptBson,
    chacha20poly1305DecryptBson: chacha20poly1305DecryptBson,
    publicKeyEncryptAESBson: publicKeyEncryptAESBson,
    privateKeyDecryptAESBson: privateKeyDecryptAESBson,
    publicKeyEncryptCHACHA20Bson: publicKeyEncryptCHACHA20Bson,
    privateKeyDecryptCHACHA20Bson: privateKeyDecryptCHACHA20Bson,
    Web3PasswordRequestEncodeBsonApi: Web3PasswordRequestEncodeBsonApi,
    Web3PasswordRequestDecodeBsonApi: Web3PasswordRequestDecodeBsonApi,
    Web3PasswordResponseEncodeBsonApi: Web3PasswordResponseEncodeBsonApi,
    Web3PasswordResponseDecodeBsonApi: Web3PasswordResponseDecodeBsonApi,
    Web3PasswordSleep2: Web3PasswordSleep2,
    Web3passwordPBKDF2: Web3passwordPBKDF2,
}