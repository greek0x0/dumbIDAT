import hashlib, time, sys


TARGET = 0xC6A579EA

def find_pattern(file_data, pattern):
    wildcard = ord(b'@')
    pat_len = len(pattern)
    return [i for i in range(len(file_data) - pat_len + 1)
            if all(p == wildcard or file_data[i + j] == p for j, p in enumerate(pattern))]

def xor(buf, key):
    for i in range(0, len(buf) - len(buf) % 4, 4):
        block = int.from_bytes(buf[i:i+4], 'little') ^ key
        buf[i:i+4] = block.to_bytes(4, 'little')

def main():
    total_payload_size = 0

    filename = sys.argv[1] if len(sys.argv) > 1 else "Klureartcik.st"
    try:
        with open(filename, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print('supply filename')
        return
    pattern = b'@@@@IDAT'
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

        sys.stdout.write(
                         f'\r[idat identifier]>: {idat_identifier.decode("ascii")} '
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

    decoded.append(0)

    sha256_hash = hashlib.sha256(decoded).hexdigest()
    expected_hash = "18bac7c368b1bb74e9d423e8e6f5bd27e0b81496b512657e1b0d19ff3f7724e9"
    print('\nsuccess hash match ==> \033[32m18bac7c368b1bb74e9d423e8e6f5bd27e0b81496b512657e1b0d19ff3f7724e9' if sha256_hash == expected_hash else '\ndidnt match target hash')
if __name__ == "__main__":
    main()
