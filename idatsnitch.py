import hashlib, time, sys
from hexdump import hexdump
import lznt1


TARGET = 0xC6A579EA

def chunky():
    total_payload_size = 0

    filename = sys.argv[1] if len(sys.argv) > 1 else "Klureartcik.st"
    with open(filename, "rb") as f:
        file_data = f.read()

    pattern = b'IDAT'
    pat_offsets = find_pattern(file_data, pattern)

    first_offset = pat_offsets[0]

    header = file_data[first_offset:first_offset+24]
    chunk_size = header[:4]
    chunk_start = header[8:12]

    xor_key = int.from_bytes(header[12:16], 'little')

    print(f'[xor key]> : 0x{xor_key:08X}')
    print(f'[target]> : 0x{TARGET:08X}')

    extracted_chunks = bytearray()

    first_chunk = None

    for offset in pat_offsets:

        chunk_header = file_data[offset:offset+24]

        if len(chunk_header) < 24:
            continue

        chunk_size = chunk_header[:4]
        idat_identifier = chunk_header[4:8]
        chunk_size_int = int.from_bytes(chunk_size, 'big')
        chunk_start = chunk_header[8:12]
        chunk_start_int = int.from_bytes(chunk_start, 'big')
        total_payload_size += chunk_size_int

        sys.stdout.write(f'\r[idat identifier]>: {idat_identifier.decode("ascii")} '
                            f'[chunk start]>: 0x{chunk_start.hex().upper()} '
                            f'[chunk size]>: 0x{total_payload_size:08X}')
        sys.stdout.flush()
        time.sleep(0.01)

        if first_chunk is None:

            if chunk_start_int != TARGET:
                continue
            first_chunk = offset
            start = offset + 24
            end = offset + 8 + chunk_size_int

            if end > len(file_data):
                continue
            chunk_data = file_data[start:end]

        else:

            start = offset + 8
            end = offset + 8 + chunk_size_int

            if end > len(file_data):
                continue
            chunk_data = file_data[start:end]

        extracted_chunks.extend(chunk_data)


    while extracted_chunks and extracted_chunks[-1] == 0:
        extracted_chunks.pop()

    decoded = bytearray(extracted_chunks)
    xor(decoded, xor_key)

    # hexdump(decoded[:1024])

    decoded.append(0)

    decompressed_payload = lznt1.decompress(decoded)

    with open('decompressed.bin', 'wb') as d:
        d.write(decompressed_payload)

    return decompressed_payload

def find_pattern(file_data, pattern):
    # wild card could be anything such as @@@@IDAT
    # doesnt necessary have to be ????IDAT, we can just target IDAT itself
    offsets = []
    start = 0
    while True:
        match = file_data.find(pattern, start)
        if match == -1:
            break
        if match >= 4:
            offsets.append(match - 4)
        start = match + 1
    return offsets

def xor(buf, key):
    size = len(buf)
    while size % 4 != 0:
        size -= 1

    key_bytes = key.to_bytes(4, 'little')
    for i in range(size):
        buf[i] ^= key_bytes[i % 4]
    return buf

def compute_hash(string, multipler):
    hash_value = 0
    for a_char in string:
        wchar = ord(a_char)
        if wchar == 0:
            break
        hash_value = (hash_value * multipler + wchar) & 0xFFFFFFFF
    return hash_value

def next_stage(payload_region, matched_dword, hash_multipler):
    module_region = 0x10DE

    loop_counter = int.from_bytes(payload_region[0xEE4:0xEE8], 'little')

    for i in range(loop_counter):
        entry_offset = module_region + 0x8A * i
        entry = payload_region[entry_offset:entry_offset + 0x8A]

        raw_string = entry.split(b'\x00', 1)[0]
        ascii_string = raw_string.decode('ascii', errors='replace')

        hash_value = compute_hash(ascii_string, hash_multipler)

        #print(f'{ascii_string} : hash = 0x{hash_value:08X}')

        if hash_value == matched_dword:
            print(f'matched DWORD: {ascii_string}')

            payload_offset = int.from_bytes(entry[0x82:0x86], 'little')
            payload_size = int.from_bytes(entry[0x86:0x8A], 'little')
            print(f'payload offset of ti module 0x{payload_offset:08X}')
            print(f'payload size used to calculate the end of payload: 0x{payload_size:08X}')

            payload_start = 0xEE4 + payload_offset
            payload_end = payload_start + payload_size

            return payload_region[payload_start:payload_end]

def main():
    matched_dword = 0x00741CF5
    hash_multipler = 0x0001003F

    # out decompressed payload
    payload = chunky()
    

    # getting the target path 
    path_offset = 0x90 

    end = payload.find(b'\00', path_offset)
    path = payload[path_offset:end].decode('ascii')
    print(f'\npath : {path}')


    # getting the target DLL 
    dll_offset = 0XF4
    end_target = payload.find(b'\x00', dll_offset)
    target_dll = payload[dll_offset:end_target].decode('ascii', errors='replace')
    print(f'target DLL : {target_dll}')


    base_offset = int.from_bytes(payload[8:12], 'little')

    payload_point = base_offset + 0x3DD
    payload_region = payload[payload_point:]

    final_payload = next_stage(payload_region, matched_dword, hash_multipler)

    if final_payload:
        with open('final_payload.bin' , 'wb') as f:
            f.write(final_payload)
    
if __name__ == "__main__":
    main()
