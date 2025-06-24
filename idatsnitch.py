import hashlib, time, sys
from hexdump import hexdump
import lznt1
TARGET = 0xC6A579EA
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

def main():
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

    sha256_hash = hashlib.sha256(decoded).hexdigest()
    expected_hash = "18bac7c368b1bb74e9d423e8e6f5bd27e0b81496b512657e1b0d19ff3f7724e9"

    print('\nsuccess hash match for xor data ==> 18bac7c368b1bb74e9d423e8e6f5bd27e0b81496b512657e1b0d19ff3f7724e9' if sha256_hash == expected_hash else '\ndidnt match target hash')
    decompressed_payload = lznt1.decompress(decoded)
    with open('decompressed.bin', 'wb') as d:
        d.write(decompressed_payload)
    function2_hash = hashlib.sha256(decompressed_payload).hexdigest()
    function2h = '9b6d65c6edd4425ee34b441b0e5c7aa34e67ebb572af92ff4f28c471a148472f'

    print('\nsuccess hash match for decompressed data ==> 9b6d65c6edd4425ee34b441b0e5c7aa34e67ebb572af92ff4f28c471a148472f' if function2_hash == function2h else '\ndidnt match target hash')

    pathOffset = 144
    Offset2 = 352
    Offset3 = 989


    pathOffset = 144
    end = decompressed_payload.find(b'\x00', pathOffset)
    length = end - pathOffset
    path = decompressed_payload[pathOffset:end].decode('ascii')
    print(f'path:  {path}')

    v20 = hexdump(decompressed_payload[:352])
    print(v20)
    payload_region = hexdump(decompressed_payload[8:Offset3])

    print('payload region dword match offset')
    payload_region_dword_match = decompressed_payload[:4318]

    hexdump(payload_region_dword_match)

    payload_region_other = decompressed_payload[:3812]
    print('payload region other offset : same as v6 in IDA')
    find_dword = payload_region_other[:138]

    for i in payload_region_dword_match:
        match = find_dword * i
        hexdump(match)



if __name__ == "__main__":
    main()
