from pwn import *

def get_salt_len():
    r.sendline('')
    reply = get_reply() # ciphertext
    prev = ''

    payload_len = 0
    while reply[:32] != prev[:32]:
        payload_len = payload_len + 1
        payload = 'A' * payload_len
        r.sendline(payload)
        prev = reply
        reply = get_reply()
    
    return 16 - payload_len + 1

#def split(x):
#    return [ x[i: i+32] for i in range (0, len(x), 32) ]

def get_reply():
    time.sleep(0.3)
    
    r.recvline()
    reply = r.recvline().decode('utf-8').strip('\r\n')
    r.recv()

    return reply

r = remote('crypto.chal.csaw.io', '1003')

print(r.recvline())
print(r.recv())

salt_len = get_salt_len()
salt_pad_len = (16 - salt_len) 
salt_pad = 'A'*salt_pad_len
print(f"salt len : {salt_len}")

block_ciphers = []
flag = ''

for block in range(1, 3):
    for n in range(1, 17):
        initial_payload = salt_pad + 'A'*(16-n)
        r.sendline(initial_payload)
        cipher = get_reply()
        block_cipher = cipher[32*block: 32*(block+1)]

        for c in string.printable:
            
            # print(f"Trying {c}")
            payload = initial_payload + flag + c
            r.sendline(payload)
            cipher2 = get_reply()
            leak_cipher = cipher2[32*block: 32*(block+1)]
            # print(f"block {block} {split(cipher2)}")
            if leak_cipher == block_cipher:
                # print(f"Found char {c} ")
                flag += c
                print(flag)
                break