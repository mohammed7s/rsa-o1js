
import { Bigint2048, rsaVerify65537 } from './rsa.js';
import bigInt from 'big-integer';

import { 
    Hash, 
    Bytes, 
    Field, 
    Gadgets, 
    Provable, 
    Struct, 
    ZkProgram, 
    provable, 
} from 'o1js';

import { console_log } from 'o1js/dist/node/bindings/compiled/node_bindings/plonk_wasm.cjs';
  


function bytesToBigInt(bytes: number[]): bigint {
// Convert the byte array to a BigInt
let result = BigInt(0);
for (let i = 0; i < bytes.length; i++) {
    result = (result << BigInt(8)) | BigInt(bytes[i]);
}
return result;
}

function charArrayToUint8Array(chars: string[]): Uint8Array {
    const bytes = new Uint8Array(chars.length);
    for (let i = 0; i < chars.length; i++) {
    bytes[i] = parseInt(chars[i], 10); // Assuming decimal string representation
    }
    return bytes;
}


(async () => {
const emlInput = {
    signature: 2937796533901000631008854690689140641270226768693786607772896083893378946198108395533513438785931181798949124505915916109223757535944407901047721805096487266307792245430443194307947639434612588085781825229002286673745779070563204991707204844050939882163781262572749550555771513235078888507301365306081030333361037728494215829049511898397148405652194469566353863123327386150506155825977956549404312556305012389030914149069897348906894159660752716454814471522831326603879677365029521905685579250953496810863071682733671861385584088939470669122929866494770741725638060444921898329222224442107461676015715071909766986049n,
    message: Buffer.from("746f3a6d6f68616d6d6564303837373440676d61696c2e636f6d0d0a6d6573736167652d69643a3c42413730464230352d343531362d343846442d394638412d41343930443338393134433740676d61696c2e636f6d3e0d0a7375626a6563743a48656c6c6f0d0a646174653a5468752c2032312044656320323032332031343a35333a3332202b303533300d0a6d696d652d76657273696f6e3a312e302028312e30290d0a66726f6d3a6d6f68616d6d656420687573617269203c6d6f68616d6d656468757361726940676d61696c2e636f6d3e0d0a636f6e74656e742d7472616e736665722d656e636f64696e673a376269740d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20633d72656c617865642f72656c617865643b20643d676d61696c2e636f6d3b20733d32303233303630313b20743d313730333135303632393b20783d313730333735353432393b20646172613d676f6f676c652e636f6d3b20683d746f3a6d6573736167652d69643a7375626a6563743a646174653a6d696d652d76657273696f6e3a66726f6d203a636f6e74656e742d7472616e736665722d656e636f64696e673a66726f6d3a746f3a63633a7375626a6563743a646174653a6d6573736167652d6964203a7265706c792d746f3b2062683d4a696b41416a77625143665158724d67494738767a782b68327446543653574364792f65457870525a62303d3b20623d"),
    //message: Buffer.from("to:mohammed08774@gmail.com\r\nmessage-id:<BA70FB05-4...more bytes here>", "utf-8"),
    body: Buffer.from("I love you ser\r\n", "utf-8"),
    bodyHash: "JikAAjwbQCfQXrMgIG8vzx+h2tFT6SWCdy/eExpRZb0=",
    signingDomain: 'gmail.com',
    publicKey: 20054049931062868895890884170436368122145070743595938421415808271536128118589158095389269883866014690926251520949836343482211446965168263353397278625494421205505467588876376305465260221818103647257858226961376710643349248303872103127777544119851941320649869060657585270523355729363214754986381410240666592048188131951162530964876952500210032559004364102337827202989395200573305906145708107347940692172630683838117810759589085094521858867092874903269345174914871903592244831151967447426692922405241398232069182007622735165026000699140578092635934951967194944536539675594791745699200646238889064236642593556016708235359n,
    selector: '20230601',
    algo: 'rsa-sha256',
    format: 'relaxed/relaxed',
    modulusLength: 2048
};

//input from helpers
const in_padded_raw = ["116","111","58","109","111","104","97","109","109","101","100","48","56","55","55","52","64","103","109","97","105","108","46","99","111","109","13","10","109","101","115","115","97","103","101","45","105","100","58","60","66","65","55","48","70","66","48","53","45","52","53","49","54","45","52","56","70","68","45","57","70","56","65","45","65","52","57","48","68","51","56","57","49","52","67","55","64","103","109","97","105","108","46","99","111","109","62","13","10","115","117","98","106","101","99","116","58","72","101","108","108","111","13","10","100","97","116","101","58","84","104","117","44","32","50","49","32","68","101","99","32","50","48","50","51","32","49","52","58","53","51","58","51","50","32","43","48","53","51","48","13","10","109","105","109","101","45","118","101","114","115","105","111","110","58","49","46","48","32","40","49","46","48","41","13","10","102","114","111","109","58","109","111","104","97","109","109","101","100","32","104","117","115","97","114","105","32","60","109","111","104","97","109","109","101","100","104","117","115","97","114","105","64","103","109","97","105","108","46","99","111","109","62","13","10","99","111","110","116","101","110","116","45","116","114","97","110","115","102","101","114","45","101","110","99","111","100","105","110","103","58","55","98","105","116","13","10","100","107","105","109","45","115","105","103","110","97","116","117","114","101","58","118","61","49","59","32","97","61","114","115","97","45","115","104","97","50","53","54","59","32","99","61","114","101","108","97","120","101","100","47","114","101","108","97","120","101","100","59","32","100","61","103","109","97","105","108","46","99","111","109","59","32","115","61","50","48","50","51","48","54","48","49","59","32","116","61","49","55","48","51","49","53","48","54","50","57","59","32","120","61","49","55","48","51","55","53","53","52","50","57","59","32","100","97","114","97","61","103","111","111","103","108","101","46","99","111","109","59","32","104","61","116","111","58","109","101","115","115","97","103","101","45","105","100","58","115","117","98","106","101","99","116","58","100","97","116","101","58","109","105","109","101","45","118","101","114","115","105","111","110","58","102","114","111","109","32","58","99","111","110","116","101","110","116","45","116","114","97","110","115","102","101","114","45","101","110","99","111","100","105","110","103","58","102","114","111","109","58","116","111","58","99","99","58","115","117","98","106","101","99","116","58","100","97","116","101","58","109","101","115","115","97","103","101","45","105","100","32","58","114","101","112","108","121","45","116","111","59","32","98","104","61","74","105","107","65","65","106","119","98","81","67","102","81","88","114","77","103","73","71","56","118","122","120","43","104","50","116","70","84","54","83","87","67","100","121","47","101","69","120","112","82","90","98","48","61","59","32","98","61","128","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","16","232","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]; 

//convert from string to uint8 array 
const in_padded = charArrayToUint8Array(in_padded_raw); 
console.log('in_padded', in_padded); 

let hashResult = Hash.SHA2_256.hash(in_padded);
console.log('hashResult', hashResult); 

// Extract the bytes array from hashResult
const hashBytes = hashResult.bytes.map(byte => byte.value);

// Convert the byte array to a BigInt
const hashBigInt = bytesToBigInt(hashBytes.map(field => Number(field)));
console.log('hashBigInt', hashBigInt); 
// Now you have hashBigInt as a BigInt representation of the hash result

// Convert publicKey to the required format, if necessary
const publicKey = Bigint2048.from(emlInput.publicKey);
const signature = Bigint2048.from(emlInput.signature);
const message = Bigint2048.from(hashBigInt); 
//const message = Bigint2048.from(bufferToBigInt(hashResult));
const modulus = publicKey; // Assuming publicKey holds the modulus

console.log("message", message); 
rsaVerify65537(message, signature, modulus);

console.log("RSA verification passed.");

})();