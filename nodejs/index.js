import {
    deriveEthPrivateKey
} from "./derive-eth-key.js";
import {
    xorTransform
} from "./xorTransform.js";
import {
    convertBase
} from "./convertBase.js";
import {
    sortByAscii
} from "./sortByAscii.js";
import {
    ethers
} from "ethers"

async function buildPassword(mnemonic, passphrase, passwordLength, charSet, passwordChunck = '', xorIndex = 0, blockIndex = 0) {
    const blockPrivateKey = await deriveEthPrivateKey(mnemonic, passphrase, blockIndex);
    const xordPrivateKey = xorTransform(blockPrivateKey, 16, xorIndex).toUpperCase();
    const tPChunck = convertBase(xordPrivateKey, 16, charSet);
    //console.log("\n", blockIndex+1, "block privateKey: ", blockPrivateKey, xordPrivateKey, "\ntChunk: ", tPChunck, tPChunck.length);
    if ((passwordChunck + tPChunck).length > passwordLength) {
        xorIndex += 1;
        return await buildPassword(mnemonic, passphrase, passwordLength, charSet, passwordChunck, xorIndex, blockIndex);
    } else if ((passwordChunck + tPChunck).length < passwordLength) {
        passwordChunck += tPChunck;
        xorIndex += 1;
        blockIndex += 1;
        //console.log("block chunck: ",passwordChunck, passwordChunck.length);
        return await buildPassword(mnemonic, passphrase, passwordLength, charSet, passwordChunck, xorIndex, blockIndex);
    } else if ((passwordChunck + tPChunck).length === passwordLength) {
        passwordChunck += tPChunck;
        //console.log("password:: ", passwordChunck, passwordChunck.length);
        return passwordChunck;
    }
}

//const window = {}//window Object for node js compatibility

window.wordlist = ethers.LangEn.wordlist()._decodeWords();

window.buildPassword = async (mnemonic, sortedPassphrase, passwordLength, charSet) => {
    return await buildPassword(mnemonic, sortedPassphrase, passwordLength, charSet);
}
window.ethers = ethers
window.sortByAscii = sortByAscii;