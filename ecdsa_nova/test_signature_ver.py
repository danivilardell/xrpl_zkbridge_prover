import ecdsa
import hashlib

message = b"test message"
public_key = '030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435'
private_key = 'D78B9735C3F26501C7337B8A5727FD53A6EFDBC6AA55984F098488561F985E23'
sig = '583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE7D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D'
message_digest = hashlib.sha512(message).digest()[0:32]
print(hashlib.sha512(message).digest().hex())
print(message_digest.hex())

vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
is_valid = vk.verify_digest(bytes.fromhex(sig), message_digest, sigdecode=ecdsa.util.sigdecode_string)
print("Signature is valid:", is_valid)

################################################################################

message2 = b"Test signing message"
sig2 = '62D404AEB68FB2D796F27E8BE53C6CBB7E41968D180C6FBA01A48E22CA1A61507BF5FDA3BE4AC148B5B3012BFD9F66A31CB447DE5DFAAA3D264A680C15ECF9E0'

message_digest2 = hashlib.sha512(message2).digest()[0:32]

is_valid = vk.verify_digest(bytes.fromhex(sig2), message_digest2, sigdecode=ecdsa.util.sigdecode_string)
print("Signature is valid:", is_valid)

################################################################################

message3 = b'''{
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
}'''
sig3 = 'C2D92C7A7A52CFC5938913A9087515D48428AECAB855C5654E163A4CA49FBD7E0A66C6C89D844952B32A2E6EBD426997B6D00BD3788E2589EDDB9B3B467BBBC8'
message_digest3 = hashlib.sha512(message3).digest()[0:32]

is_valid = vk.verify_digest(bytes.fromhex(sig3), message_digest3, sigdecode=ecdsa.util.sigdecode_string)
print("Signature is valid:", is_valid)


import binascii

def decompress_public_key(public_key_hex):
    # Convert the hexadecimal public key to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Extract the x-coordinate from the public key bytes (excluding the prefix byte)
    x_hex = public_key_bytes[1:33]

    # Convert the x-coordinate to an integer
    x_int = int.from_bytes(x_hex, 'big')

    p = 2**256-2**32-2**10+2**6-2**4-1
    exp = (p+1)//4
    y0 = pow(x_int**3+7, exp, p)
    
    prefix_byte = public_key_bytes[0]
    if prefix_byte == 0x03:
        y_int = y0
    elif prefix_byte == 0x02:
        y_int = p-y0
        
    return (x_int, y_int)

# Define SECP256K1 order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Given public key
public_key = '030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435'

# Find the uncompressed 2-point representation
uncompressed_public_key = decompress_public_key(public_key)
print("Uncompressed Public Key:", uncompressed_public_key)


def bigint_to_array(n, k, x):
    mod = 1 << n
    ret = []
    x_temp = x
    for idx in range(k):
        ret.append(str(x_temp % mod))
        x_temp //= mod
    return ret

import json 

x = bigint_to_array(64, 4, 6037173443773997886668471417388836682686879880556617528298848505798187996213)
y = bigint_to_array(64, 4, 19699927397356177930421515225934715870789393408842078322357691991754169069365)
m = bigint_to_array(64, 4, 58235472112234703381641336702124261585738700804510090507957043260272319007637)
r = bigint_to_array(64, 4, 39907013987188434849298256294103991816922287541021566993077882528160047416302)
s = bigint_to_array(64, 4, 56575393924524104884747990248535206881991919574170541325409056135393305685805)

print(json.dumps(x))
print(json.dumps(y))
print(json.dumps(m))
print(json.dumps(r))
print(json.dumps(s))


# DER-encoded signature
der_signature = bytes.fromhex('30440220583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE02207D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D')

# Check if the signature starts with the DER sequence tag (0x30)
if der_signature[0] != 0x30:
    raise ValueError("Invalid DER encoding: Missing sequence tag")

# Extract the length of the sequence
sequence_length = der_signature[1]

# Ensure the length of the sequence matches the length of the signature
if sequence_length != len(der_signature) - 2:
    raise ValueError("Invalid DER encoding: Incorrect sequence length")

# Extract 'r' and 's' from the DER-encoded signature
r_index = 4  # Skip the sequence tag (0x30) and the length byte for 'r'
r_length = der_signature[3]  # Length of 'r'
r = int.from_bytes(der_signature[r_index:r_index+r_length], 'big')

s_index = r_index + r_length + 2  # Skip 'r', the integer tag (0x02), and the length byte for 's'
s_length = der_signature[r_index + r_length + 1]  # Length of 's'
s = int.from_bytes(der_signature[s_index:s_index+s_length], 'big')

print("r:", r)
print("s:", s)

p = 2**256-2**32-2**10+2**6-2**4-1
x = 6037173443773997886668471417388836682686879880556617528298848505798187996213
exp = (p+1)//4
y = pow(x**3+7, exp, p)

print(x, y)
print(y**2 % p)
print(pow(x, 3, p))


public_key = "029D19FB0940E5C0D85873FA711999944A687D129DA5C33E928C2751FC1B31EB32"
hash = "25498AF5C457C3BFC3C6F1301F21265CD1080E43323358A26C9F0864830B924C"
sig = "DD29DCAC825EF9E22D260395C2113A2A83EEA02B9F2A51BD6BF783CE4A7C52295245B90757EFB26C69C547CAE27600FC35465D1964CECA88A12A20CF3CF9CECF"

vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
is_valid = vk.verify_digest(bytes.fromhex(sig), bytes.fromhex(hash), sigdecode=ecdsa.util.sigdecode_string)
print("Signature is valid:", is_valid)


def convert_hex_to_string(hex_string):    
    # Split the hex string into pairs of characters
    hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    
    # Convert each hex pair to decimal and join them with ', ' separator
    decimal_values = [int(hex_pair, 16) for hex_pair in hex_pairs]
    formatted_string = ", ".join(["0x{:02X}".format(value) for value in decimal_values])
    
    return "{" + formatted_string + "}"
V
# Example hexadecimal string
hex_string = "22800000012605206BC9292D625C7F3A79FB128736CE51EF515AE2F053594713CE1303137E8C141095D7A0B37DDC7B961C694DE41D4D3A55545017905E6C0A433634F7B84FCC6E26FE0E18207C78B408570E93EEEDA714183C72B050191874380B869F17469BE55AC0DF6D1151B88C9E22F7DD81D6CDF2B1FD362F3495732103C70A093F62EBE1C734F98E48B921A38EF0E2DF6CA8AFE094ECC842489A198DE5764730450221009A4542494273F645D9A8C66B888E8DF266E10306F0C009E369F8114325E704CC022006C269446A9A737D0CCD5E90C80BC8E2E8AB91C22D4372707243C3591AE78E13"

# Convert and print the result
print(convert_hex_to_string(hex_string))