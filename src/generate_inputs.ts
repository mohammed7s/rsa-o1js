import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim/index.js"; 
import { DKIMVerify } from "./dkim.js";
import {Bytes} from 'o1js'; 


import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';


const __dirname = path.dirname(fileURLToPath(import.meta.url));

// create eml folder in root and place en aml file you wish to verify there  
const filePath = path.join(__dirname, '../../eml/gitcoin.eml'); 
const rawEmail = fs.readFileSync(filePath, "utf8");
console.log(rawEmail);


// parse raw email 
//This method needs to be online to check public key of the domain specified in header
const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));

const signature = dkimResult.signature; 
const publicKey = dkimResult.publicKey; 
const body = dkimResult.body; 
const bodyHash = dkimResult.bodyHash; 
const message = dkimResult.message; 

// console.log('1', dkimResult); 
// console.log('2', signature); 
// console.log('3', publicKey); 
// console.log('4', body); 
// console.log('5', bodyHash);
// //console.log('6', bufferToBigInt(message));
// console.log('6', message)


DKIMVerify(Bytes.from(message), signature, publicKey)



// Write message, signature, and publicKey to a JSON file for testing purposes offline
// const data = {
//   message: message.toString('hex'),
//   signature: signature.toString(),
//   publicKey: publicKey.toString()
// };

// const jsonData = JSON.stringify(data, null, 2);
// fs.writeFileSync('dkim_data.json', jsonData);
// console.log('data', data); 
// console.log('Data saved to dkim_data.json');

