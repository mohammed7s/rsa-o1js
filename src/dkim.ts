import { Bigint2048, rsaVerify65537 } from './rsa.js';
import { 
    Hash, 
    Bytes, 
} from 'o1js';

export { 
    DKIMVerify
} 

/**
 * Verifies a DKIM signature using the provided message, signature, and public key.
 * 
 * @param {Bytes} message The message to be verified, represented as a Bytes object.
 * @param {bigint} signature The signature to be verified, represented as a bigint.
 * @param {bigint} publicKey The public key used for verification, represented as a bigint.
 * @returns {void} This function does not return any value.
 */
function DKIMVerify(
    message: Bytes,
    signature: bigint,
    publicKey: bigint
) {
    // hash the message 
    let preimageBytes = Bytes(message.length).from(message); // convert the preimage to bytes
    let hash = Hash.SHA2_256.hash(preimageBytes); // hash the preimage using o1js
    // get emLen : Calculate the length of the encoded message in bytes
    const modBits = publicKey.toString(2).length;
    const emLen = Math.ceil(modBits / 8);

    // pkcs15encode hash  
    let paddedHash = pkcs1v15Encode(hash,emLen); 
    // convert all to bigint2048
    let final_message = Bigint2048.from(BigInt("0x"+ paddedHash.toHex())); 
    let final_signature =  Bigint2048.from(BigInt(signature));
    let final_modulus = Bigint2048.from(BigInt(publicKey)); 
    // rsaverify
    rsaVerify65537(final_message, final_signature, final_modulus);
}


/**
* Still to do/check/address: 
* 1. since the digest in our case is 32ytes (sha256) maybe we can have emlen constant? its derived 
* from the publickey so check if it changes from 1024 to 2048 occasionally? or 4096?
* 2. length check is it necessary? 
* 3. The RFC gurantees 8 octets of '0xFF' paddings. Need to incorporate this. 
*/
function pkcs1v15Encode(
    digest: Bytes, 
    _emLen: number
) {
    // this represents the SHA256 algorithm as per the RFC3447 9.2 
    const digestAlgorithm = Bytes(19).fromHex('3031300d060960864801650304020105000420');
    // caculate length of padding needed. 
    const PSLength = _emLen - digestAlgorithm.length - digest.length - 3; 

    // Still not sure if this check is necessary. I see it in the Python implementation and also in
    // circom zkemail: https://github.com/zkemail/zk-email-verify/blob/fd7558af4ebf51be0bffb0f74437b0e7c996f5da/packages/circuits/helpers/rsa.circom#L110
    // Given that we will have at minimum 1024bit RSA /128 bytes and always use sha256 (32bytes) for the hash. 
    if (_emLen < (digest.length + digestAlgorithm.length + 11)) {
        throw new Error(`Selected hash algorithm has a too long digest (${digest.length + digestAlgorithm.length} bytes).`);
    }
    // Check if this is acceptable to do in provable context. new Array? 
    const PS = new Array(PSLength).fill(0xFF);
    const PSBytes = Bytes(PSLength).from(PS); 

    // create padding with '0001' before the 'FF' sequence and then end with '00' 
    const pad1 = Bytes(2).fromHex('0001'); 
    const pad2 = Bytes(1).fromHex('00'); 
    let padding = pad1.bytes.concat(PSBytes.bytes).concat(pad2.bytes); 

    // concat digestAlgorithm + digest 
    let digestinfo = digestAlgorithm.bytes.concat(digest.bytes); 
    //final conact: padding + digestInfo 
    let x = Bytes(_emLen).from(padding.concat(digestinfo)); 
    return x 
}