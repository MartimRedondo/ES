from cbc_mac import *


def main ():

    key_file = "key"
    with open(key_file, 'rb') as f:
        key_64 = f.read().strip()
    #print (key_64)
    key = base64.b64decode(key_64)

    message1_file = "hm"
    with open(message1_file, 'rb') as f:
        message1 = f.read()
    #print (message1)

    message2_file = "hm2"
    with open(message2_file, 'rb') as f:
        message2 = f.read()
    #print(message2)

    msg1 = padding_by_me(message1)
    msg2 = padding_by_me(message2)

    tag1 = generate_tag(key, msg1)
    tag2 = generate_tag(key, msg2)

    modified_first_block = xor_bytes(msg2[:16], tag1)

    forged_message = msg1 + modified_first_block + msg2[16:]

    forged_mac = generate_tag(key, forged_message)

    if hmac.compare_digest(forged_mac, tag2):
        print("\n[!]Attack successful: The forged message has a valid MAC!")
    else:
        raise InvalidTag("[!]Attack Failed: Tag Mac not valid!")

if __name__ == "__main__":
    main()