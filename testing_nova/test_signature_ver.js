const rippleKeypairs = require('ripple-keypairs');
const xrpl = require('xrpl');


function stringToHex(inputString) {
    let hexString = '';
    for (let i = 0; i < inputString.length; i++) {
        let hex = inputString.charCodeAt(i).toString(16);
        hexString += hex.padStart(2, '0'); // Ensure each hex value is at least 2 characters long
    }
    return hexString;
}

const seed = "sp5fghtJtpUorTwvof1NpDXAzNwf5";

console.log(seed)

const keypair = rippleKeypairs.deriveKeypair(seed);

console.log(keypair)

/*const message = `{
    "id": "example_ledger_req",
    "result": {
      "ledger": {
        "account_hash": "B8B2C0C3F9E75E3AEE31D467B2544AB56244E618890BA58679707D6BFC0AF41D",
        "close_flags": 0,
        "close_time": 752188602,
        "close_time_human": "2023-Nov-01 21:16:42.000000000 UTC",
        "close_time_resolution": 10,
        "closed": true,
        "ledger_hash": "1BEECD5D21592EABDEF98D8E4BC038AD10B5700FF7E98011870DF5D6C2A2F39B",
        "ledger_index": "83626901",
        "parent_close_time": 752188601,
        "parent_hash": "6B32CFC42B32C5FB90019AE17F701D96B499A4C8E148A002E18135A434A19D98",
        "total_coins": "99988256314388830",
        "transaction_hash": "21586C664DC47E12AF34F22EBF1DB55D23F8C98972542BAC0C39B1009CAC84D4"
      },
      "ledger_hash": "1BEECD5D21592EABDEF98D8E4BC038AD10B5700FF7E98011870DF5D6C2A2F39B",
      "ledger_index": 83626901,
      "validated": true
    },
    "status": "success",
    "type": "response"
}`;*/
let message = "test message"

let hexMessage = stringToHex(message);

const signature = rippleKeypairs.sign(hexMessage, keypair.privateKey); 

console.log(signature)

const isValid = rippleKeypairs.verify(hexMessage, signature, keypair.publicKey)

console.log(isValid)

