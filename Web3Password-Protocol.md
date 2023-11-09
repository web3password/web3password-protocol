# Web3Password Protocol
```shell
version + dataLength + dataBinary

big endian
version - 2 bytes, fixed string: "01"
dataLength - 4 bytes, length of dataBinary
dataBinary - bytes by bson

```

## Example
```
/web3password/addCredential
https://github.com/web3password/web3password-protocol/blob/main/Web3Password-Tools/web3password-api-encode-decode-bson-demo.js


```