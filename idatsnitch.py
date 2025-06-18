import hashlib
import os

def swap32(b):
    # reverse bytes order
    return b[::-1]

def find_pattern(data, pattern):
    # find all places in data where pattern fits
    # you can use @@@@ as wildcard chars they match anything
    wildcard = ord(b'@')
    matches = []
    for i in range(len(data) - len(pattern) + 1):
        for j, p in enumerate(pattern):
            # break out the pattern if its no valid and the byte at this posiiton doesnt match the pattern byte
            if p != wildcard and data[i + j] != p:
                break
        else:
            # if we didnt break it means pattern matched here
            matches.append(i)
    return matches

def xor_decrypt_4bytes(buf, start, key):
    # xor decrypt 4 bytes blocks at start offseyt
    # only works on multiples of 4 bytes length
    end = len(buf) - (len(buf) - start) % 4
    for i in range(start, end, 4):
        # convert 4 bytes to int for xor
        block = int.from_bytes(buf[i:i+4], 'little')
        # xor with key
        decrypted = block ^ key
        # write decrypted bytes back
        buf[i:i+4] = decrypted.to_bytes(4, 'little')

def trim_header(buf):
    # remove this 16 byte header if it exists at start
    header = bytes.fromhex("C6A579EAE86C7BD342841500DE392000")
    if buf.startswith(header):
        return buf[16:]
    return buf

def main():
    with open("Klureartcik.st", "rb") as f:
        data = f.read()
    print(f"file loaded, size: {len(data)} bytes")

    print("looking for pattern @@@@IDAT in file data ")

    # when it matches the pattern it stores these as offsets

    offsets = find_pattern(data, b"@@@@IDAT")


    print(f"found {len(offsets)} offset for  chunk ")


    global_alloc_buffer = bytearray()
    first_chunk_found = False


    # loop over every place off offset found from our pattern
    for i, offset in enumerate(offsets):
        #print(f"processing chunk {i+1} at offset {hex(offset)}")
        # target section
        raw = data[offset:offset+24]

        # swapped endian chunk size first 4
        chunk_size = int.from_bytes(swap32(raw[:4]), "little")


        # IDAT part
        IDAT = int.from_bytes(swap32(raw[4:8]), "big")

        magic = int.from_bytes(swap32(raw[8:12]), "big")

        # skip this chunk since its not used
        if offset == 0x15B0EA and chunk_size == 0x2000 and IDAT == 0x54414449 and magic == 0x65E001A5:
            # because the payload gets cut off here
            print("skipping  chunk at 0x15B0EA")
            continue

        if not first_chunk_found:
            #beginnign of where we search for each  chunk
            if magic != 0xEA79A5C6:
                print("skipping ")
                continue
            print("first valid chunk found, starting to collect chunk")
            first_chunk_found = True


        # skip first 8 bytes at offset
        chunk = data[offset+8:offset+8+chunk_size]


        global_alloc_buffer.extend(chunk)


    start_seq = bytes([0xA5,0x01,0xE0,0x65,0xD6,0xA5,0x09,0xD9,0xF1,0x74,0xF6,0xAA,0x0F])
    end_seq   = bytes([0xE8,0x63,0x7B,0xDC,0xE8,0x63,0x7B,0xDC,0xE8,0x63,0x74,0xD3,0xE7,0x6C,0x74,0xD3])

    # find these bytes in the data
    start_offset = data.find(start_seq)


    end_offset = data.find(end_seq, start_offset + len(start_seq))

    print(f"special chunk found from {hex(start_offset)} to {hex(end_offset)}")

    global_alloc_buffer.extend(data[start_offset:end_offset + len(end_seq)])

    xor_key = 0xD37B6CE8

    xor_start_seq = b'\xBA\xD5\x7B\xD3\xE8'

    decrypt_offset = global_alloc_buffer.find(xor_start_seq)

    print(f"found xor start at {hex(decrypt_offset)}, do  xor decrypt...")
    # do xor decrypt
    xor_decrypt_4bytes(global_alloc_buffer, decrypt_offset, xor_key)

    print("xor decrypt done")

    output = trim_header(global_alloc_buffer) + b'\x0C\x00'
    with open("function1.bin", "wb") as out_file:
        out_file.write(output)

    hash1 = hashlib.sha256(output).hexdigest()
    expected_hash = '18bac7c368b1bb74e9d423e8e6f5bd27e0b81496b512657e1b0d19ff3f7724e9'

    if hash1 != expected_hash:
        print('suffer')
        exit(1)
    else:
        print(f'hash matched: {hash1}')

if __name__ == "__main__":
    main()
#    os.system("xxd -l 200 function1.bin")
