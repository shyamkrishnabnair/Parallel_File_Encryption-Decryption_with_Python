"""
parallel_files_crypto.py

Encrypt/decrypt multiple files in parallel. Builds on the PFC single-file implementation
but adds a top-level file-level parallel executor so many files can be processed at once.

Design decisions:
- We avoid nested ProcessPoolExecutors: chunk-level encryption still supports parallelism
  via processes, but when running many files in parallel (file-level parallelism) we
  force chunk-level work to use a single worker per file (workers=1) to prevent
  process oversubscription and nested process pools.
- Alternatively you can run file-level parallelism=1 and let each file use chunk-level
  parallel workers (good for single large file). Tune with --file-workers and --chunk-workers.

Usage examples:
  Encrypt multiple files (3 files) using 3 parallel file-workers, each file will use 1 chunk-worker:
    python parallel_files_crypto.py encrypt -I a.mp4 b.mov c.zip --file-workers 3 --chunk-workers 1

  Encrypt a whole directory (recursively by default):
    python parallel_files_crypto.py encrypt -D ./data --file-workers 6

  Decrypt multiple files:
    python parallel_files_crypto.py decrypt -I a.mp4.pfc b.mov.pfc --file-workers 4

Requirements:
  pip install cryptography tqdm

"""

import argparse
import os
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial
from typing import Tuple, List

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from tqdm import tqdm

MAGIC = b'PFC\x01'
SALT_LEN = 16
NONCE_LEN = 12
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB


def derive_key(password: bytes, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password)


def _encrypt_chunk(args: Tuple[int, bytes, bytes]) -> Tuple[int, bytes, bytes]:
    index, chunk_bytes, key = args
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, chunk_bytes, associated_data=None)
    return index, nonce, ct


def _decrypt_chunk(args: Tuple[int, bytes, bytes]) -> Tuple[int, bytes]:
    index, nonce, ciphertext, key = args
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise InvalidTag(f"Authentication failed for chunk {index}")
    return index, pt


def encrypt_file(in_path: str, out_path: str, password: str, chunk_size: int = DEFAULT_CHUNK_SIZE, workers: int = None):
    """Encrypt a single file. This function may itself use a ProcessPoolExecutor
    for chunk encryption if workers is None or >1. To avoid nested pools, callers
    doing file-level parallelism should pass workers=1."""
    password_bytes = password.encode('utf-8')
    salt = os.urandom(SALT_LEN)
    key = derive_key(password_bytes, salt)

    file_size = os.path.getsize(in_path)
    num_chunks = (file_size + chunk_size - 1) // chunk_size

    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(MAGIC)
        fout.write(struct.pack('B', SALT_LEN))
        fout.write(salt)
        fout.write(struct.pack('<Q', chunk_size))
        fout.write(struct.pack('<Q', num_chunks))

        if workers is None:
            # default chunk-level workers: CPU-1
            workers = max(1, (os.cpu_count() or 1) - 1)

        # If workers == 1 we'll encrypt sequentially (no ProcessPoolExecutor)
        if workers <= 1:
            with tqdm(total=num_chunks, unit='chunk') as pbar:
                for idx in range(num_chunks):
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    aesgcm = AESGCM(key)
                    nonce = os.urandom(NONCE_LEN)
                    ct = aesgcm.encrypt(nonce, chunk, associated_data=None)
                    fout.write(struct.pack('<Q', idx))
                    fout.write(struct.pack('B', len(nonce)))
                    fout.write(nonce)
                    fout.write(struct.pack('<Q', len(ct)))
                    fout.write(ct)
                    pbar.update(1)
        else:
            pool = ProcessPoolExecutor(max_workers=workers)
            futures = {}
            for idx in range(num_chunks):
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                fut = pool.submit(_encrypt_chunk, (idx, chunk, key))
                futures[fut] = idx

            results_buffer = {}
            next_to_write = 0
            with tqdm(total=num_chunks, unit='chunk') as pbar:
                for fut in as_completed(futures):
                    idx, nonce, ct = fut.result()
                    results_buffer[idx] = (nonce, ct)
                    while next_to_write in results_buffer:
                        nonce_w, ct_w = results_buffer.pop(next_to_write)
                        fout.write(struct.pack('<Q', next_to_write))
                        fout.write(struct.pack('B', len(nonce_w)))
                        fout.write(nonce_w)
                        fout.write(struct.pack('<Q', len(ct_w)))
                        fout.write(ct_w)
                        next_to_write += 1
                        pbar.update(1)
            pool.shutdown(wait=True)


def decrypt_file(in_path: str, out_path: str, password: str, workers: int = None):
    password_bytes = password.encode('utf-8')

    with open(in_path, 'rb') as fin:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError('Input file is not a PFC encrypted file or version mismatch')
        salt_len = struct.unpack('B', fin.read(1))[0]
        salt = fin.read(salt_len)
        chunk_size = struct.unpack('<Q', fin.read(8))[0]
        num_chunks = struct.unpack('<Q', fin.read(8))[0]

        key = derive_key(password_bytes, salt)

        if workers is None:
            workers = max(1, (os.cpu_count() or 1) - 1)

        # If workers == 1, decrypt sequentially
        if workers <= 1:
            with open(out_path, 'wb') as fout, tqdm(total=num_chunks, unit='chunk') as pbar:
                for _ in range(num_chunks):
                    header = fin.read(8)
                    if not header:
                        break
                    idx = struct.unpack('<Q', header)[0]
                    nonce_len = struct.unpack('B', fin.read(1))[0]
                    nonce = fin.read(nonce_len)
                    ct_len = struct.unpack('<Q', fin.read(8))[0]
                    ct = fin.read(ct_len)
                    aesgcm = AESGCM(key)
                    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
                    fout.write(pt)
                    pbar.update(1)
        else:
            pool = ProcessPoolExecutor(max_workers=workers)
            pending = {}
            buffer = {}
            next_to_write = 0
            with open(out_path, 'wb') as fout, tqdm(total=num_chunks, unit='chunk') as pbar:
                for _ in range(num_chunks):
                    header = fin.read(8)
                    if not header:
                        break
                    idx = struct.unpack('<Q', header)[0]
                    nonce_len = struct.unpack('B', fin.read(1))[0]
                    nonce = fin.read(nonce_len)
                    ct_len = struct.unpack('<Q', fin.read(8))[0]
                    ct = fin.read(ct_len)
                    fut = pool.submit(_decrypt_chunk, (idx, nonce, ct, key))
                    pending[fut] = idx

                    done_now = [f for f in list(pending.keys()) if f.done()]
                    for f in done_now:
                        i, pt = f.result()
                        pending.pop(f)
                        if i == next_to_write:
                            fout.write(pt)
                            next_to_write += 1
                            pbar.update(1)
                            # flush buffer
                            while next_to_write in buffer:
                                fout.write(buffer.pop(next_to_write))
                                next_to_write += 1
                                pbar.update(1)
                        else:
                            buffer[i] = pt

                # wait remaining
                for f in as_completed(list(pending.keys())):
                    i, pt = f.result()
                    if i == next_to_write:
                        fout.write(pt)
                        next_to_write += 1
                        pbar.update(1)
                        while next_to_write in buffer:
                            fout.write(buffer.pop(next_to_write))
                            next_to_write += 1
                            pbar.update(1)
                    else:
                        buffer[i] = pt

            pool.shutdown(wait=True)


def process_encrypt_wrapper(args):
    infile, outfile, password, chunk_size, chunk_workers = args
    # to avoid nested process pools we pass chunk_workers as 1 when file-level parallelism >1
    encrypt_file(infile, outfile, password, chunk_size=chunk_size, workers=chunk_workers)
    return infile, outfile


def process_decrypt_wrapper(args):
    infile, outfile, password, chunk_workers = args
    decrypt_file(infile, outfile, password, workers=chunk_workers)
    return infile, outfile


def collect_input_files(inputs: List[str], input_dir: str, recursive: bool) -> List[str]:
    files = []
    if inputs:
        for p in inputs:
            if os.path.isdir(p):
                for root, _, filenames in os.walk(p):
                    for fn in filenames:
                        files.append(os.path.join(root, fn))
                    if not recursive:
                        break
            else:
                files.append(p)
    if input_dir:
        for root, _, filenames in os.walk(input_dir):
            for fn in filenames:
                files.append(os.path.join(root, fn))
            if not recursive:
                break
    # remove duplicates and non-files
    files = [f for f in dict.fromkeys(files) if os.path.isfile(f)]
    return files


def get_password(prompt: str) -> str:
    try:
        import getpass
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def main():
    parser = argparse.ArgumentParser(description='Parallel Files Encryptor/Decryptor (PFC bulk)')
    sub = parser.add_subparsers(dest='cmd')

    p_enc = sub.add_parser('encrypt')
    p_enc.add_argument('-I', '--inputs', nargs='*', help='Input files or directories', default=[])
    p_enc.add_argument('-D', '--input-dir', help='Input directory to scan', default=None)
    p_enc.add_argument('-o', '--output-dir', help='Output directory (defaults to same dir as input)', default=None)
    p_enc.add_argument('--recursive', action='store_true', help='Scan directories recursively')
    p_enc.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE)
    p_enc.add_argument('--file-workers', type=int, default=4, help='Number of files to process in parallel')
    p_enc.add_argument('--chunk-workers', type=int, default=1, help='Chunk-level workers per file (use 1 when doing file-level parallelism)')

    p_dec = sub.add_parser('decrypt')
    p_dec.add_argument('-I', '--inputs', nargs='*', help='Input files or directories', default=[])
    p_dec.add_argument('-D', '--input-dir', help='Input directory to scan', default=None)
    p_dec.add_argument('-o', '--output-dir', help='Output directory (defaults to same dir as input)', default=None)
    p_dec.add_argument('--recursive', action='store_true', help='Scan directories recursively')
    p_dec.add_argument('--file-workers', type=int, default=4, help='Number of files to process in parallel')
    p_dec.add_argument('--chunk-workers', type=int, default=1, help='Chunk-level workers per file')

    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)

    password = get_password('Password: ')

    if args.cmd == 'encrypt':
        files = collect_input_files(args.inputs, args.input_dir, args.recursive)
        if not files:
            print('No input files found.')
            sys.exit(1)

        tasks = []
        for infile in files:
            outdir = args.output_dir or os.path.dirname(infile)
            fn = os.path.basename(infile) + '.pfc'
            outfile = os.path.join(outdir, fn)
            tasks.append((infile, outfile, password, args.chunk_size, args.chunk_workers))

        with ProcessPoolExecutor(max_workers=args.file_workers) as pool:
            futures = {pool.submit(process_encrypt_wrapper, t): t[0] for t in tasks}
            for fut in as_completed(futures):
                infile = futures[fut]
                try:
                    _, outfile = fut.result()
                    print(f'Encrypted: {infile} -> {outfile}')
                except Exception as e:
                    print(f'Failed to encrypt {infile}: {e}')

    elif args.cmd == 'decrypt':
        files = collect_input_files(args.inputs, args.input_dir, args.recursive)
        if not files:
            print('No input files found.')
            sys.exit(1)

        tasks = []
        for infile in files:
            outdir = args.output_dir or os.path.dirname(infile)
            # remove .pfc if present
            if infile.endswith('.pfc'):
                fn = os.path.basename(infile)[:-4]
            else:
                fn = os.path.basename(infile) + '.dec'
            outfile = os.path.join(outdir, fn)
            tasks.append((infile, outfile, password, args.chunk_workers))

        with ProcessPoolExecutor(max_workers=args.file_workers) as pool:
            futures = {pool.submit(process_decrypt_wrapper, t): t[0] for t in tasks}
            for fut in as_completed(futures):
                infile = futures[fut]
                try:
                    _, outfile = fut.result()
                    print(f'Decrypted: {infile} -> {outfile}')
                except Exception as e:
                    print(f'Failed to decrypt {infile}: {e}')

if __name__ == '__main__':
    main()
