"""
pfc_fastapi_backend.py

FastAPI backend to encrypt/decrypt one-or-many files using the PFC format.

Features:
- /encrypt and /decrypt endpoints accept multipart form uploads (multiple files), a password,
  and optional tuning parameters (chunk_size, file_workers, chunk_workers).
- Streams results back as a single file: if one input -> single processed file; if many -> a ZIP archive.
- Writes uploads to a temporary directory, invokes the existing parallel_files_crypto implementation
  (functions encrypt_file and decrypt_file) to perform crypto work in separate processes to avoid blocking.
- Cleans up temporary files after response.

Security notes (read before deploying):
- Always run behind HTTPS (nginx / cloud load balancer) to protect passwords in transit.
- Set sensible limits for upload size and request rate (e.g., via middleware or reverse proxy).
- Do NOT persist uploaded files longer than needed. This script removes temp files after response.

Requirements:
  pip install fastapi uvicorn python-multipart aiofiles

Usage:
  uvicorn pfc_fastapi_backend:app --host 0.0.0.0 --port 8000

Example curl (single file):
  curl -F "password=secret" -F "files=@test.txt" http://localhost:8000/encrypt -o test.txt.pfc

Example curl (multiple files -> zip returned):
  curl -F "password=secret" -F "files=@a.txt" -F "files=@b.jpg" http://localhost:8000/encrypt -o out.zip

Note: this file expects that the functions `encrypt_file` and `decrypt_file` are available
in the Python path (for example from parallel_files_crypto.py / parallel_files_crypto module).
If both files are in the same directory, Python will import them directly.
"""

"""
pfc_fastapi_backend.py

FastAPI backend to encrypt/decrypt one-or-many files using the PFC format.

(edited: adds BackgroundTasks cleanup, robust imports and comments marking changes)
"""

import os
import shutil
import tempfile
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks  # CHANGED: import BackgroundTasks here
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

# CHANGED: Try importing encrypt/decrypt from likely module names (robust)
#   - parallel_files_crypto.py (bulk version)
#   - parallel_file_crypto.py (single-file)
#   - app.py (if you named the module app)
encrypt_file = decrypt_file = None
_import_errors = []
for modname in ("parallel_files_crypto", "parallel_file_crypto", "app", "parallel_file_crypto_backend"):
    try:
        m = __import__(modname)
        # expect functions at top-level of module
        if hasattr(m, "encrypt_file") and hasattr(m, "decrypt_file"):
            encrypt_file = getattr(m, "encrypt_file")
            decrypt_file = getattr(m, "decrypt_file")
            break
    except Exception as e:
        _import_errors.append((modname, str(e)))

if encrypt_file is None or decrypt_file is None:
    # CHANGED: helpful error with attempted modules
    attempted = ", ".join([n for n, _ in _import_errors])
    raise RuntimeError(
        "Could not import encrypt/decrypt functions. Make sure parallel_files_crypto.py is on PYTHONPATH "
        f"or rename module accordingly. Attempted: {attempted}"
    )

app = FastAPI(title='PFC FastAPI Backend')

# allow your frontend origin during development:
origins = [
    "*"  # CHANGED: permissive for dev; restrict in production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # use specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper to write UploadFile to disk
async def save_upload_to_tmp(upload: UploadFile, dest_dir: str) -> str:
    dest_path = os.path.join(dest_dir, upload.filename)
    with open(dest_path, 'wb') as out_f:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            out_f.write(chunk)
    return dest_path

def cleanup_dir(path):
    import shutil, os
    try:
        shutil.rmtree(path)
    except Exception:
        pass

def _process_encrypt_task(args):
    infile, outfile, password, chunk_size, chunk_workers = args
    # call encrypt_file (this function is CPU bound so it's fine to run in a process)
    encrypt_file(infile, outfile, password, chunk_size=chunk_size, workers=chunk_workers)
    return outfile

def _process_decrypt_task(args):
    infile, outfile, password, chunk_workers = args
    decrypt_file(infile, outfile, password, workers=chunk_workers)
    return outfile

@app.post('/encrypt')
async def encrypt_endpoint(
    password: str = Form(...),
    files: List[UploadFile] = File(...),
    chunk_size: int = Form(4 * 1024 * 1024),
    file_workers: int = Form(2),
    chunk_workers: int = Form(1),
    background_tasks: BackgroundTasks = None,  # CHANGED: proper injection of BackgroundTasks
):
    if not files:
        raise HTTPException(status_code=400, detail='No files uploaded')

    tmpdir = tempfile.mkdtemp(prefix='pfc_upload_')
    outdir = tempfile.mkdtemp(prefix='pfc_out_')
    processed_outputs = []

    try:
        # Save uploads to disk
        saved_paths = []
        for f in files:
            path = await save_upload_to_tmp(f, tmpdir)
            saved_paths.append(path)

        # Prepare tasks
        tasks = []
        for p in saved_paths:
            outfn = os.path.basename(p) + '.pfc'
            outfile = os.path.join(outdir, outfn)
            tasks.append((p, outfile, password, chunk_size, chunk_workers))

        # Run file-level parallelism in process pool
        with ProcessPoolExecutor(max_workers=file_workers) as pool:
            futures = {pool.submit(_process_encrypt_task, t): t for t in tasks}
            for fut in as_completed(futures):
                try:
                    outpath = fut.result()
                    processed_outputs.append(outpath)
                except Exception as e:
                    traceback.print_exc()
                    # schedule cleanup before raising so temp dirs aren't leaked
                    if background_tasks:
                        background_tasks.add_task(cleanup_dir, tmpdir)
                        background_tasks.add_task(cleanup_dir, outdir)
                    raise HTTPException(status_code=500, detail=f'Encryption failed: {e}')

        # Return single file directly or zip multiple
        if len(processed_outputs) == 1:
            # CHANGED: schedule cleanup after response is complete
            if background_tasks:
                background_tasks.add_task(cleanup_dir, tmpdir)
                background_tasks.add_task(cleanup_dir, outdir)
            return FileResponse(processed_outputs[0],
                                media_type='application/octet-stream',
                                filename=os.path.basename(processed_outputs[0]))
        else:
            zip_base = os.path.join(outdir, 'pfc_results')
            zip_path = zip_base + '.zip'
            shutil.make_archive(zip_base, 'zip', outdir)
            # CHANGED: schedule cleanup after response finishes
            if background_tasks:
                background_tasks.add_task(cleanup_dir, tmpdir)
                background_tasks.add_task(cleanup_dir, outdir)
            return FileResponse(zip_path, media_type='application/zip', filename='pfc_results.zip')

    finally:
        # CHANGED: we do not aggressively delete here; cleanup scheduled via BackgroundTasks above
        pass

@app.post('/decrypt')
async def decrypt_endpoint(
    password: str = Form(...),
    files: List[UploadFile] = File(...),
    file_workers: int = Form(2),
    chunk_workers: int = Form(1),
    background_tasks: BackgroundTasks = None,  # CHANGED: injected
):
    if not files:
        raise HTTPException(status_code=400, detail='No files uploaded')

    tmpdir = tempfile.mkdtemp(prefix='pfc_upload_')
    outdir = tempfile.mkdtemp(prefix='pfc_out_')
    processed_outputs = []

    try:
        # Save uploads to disk
        saved_paths = []
        for f in files:
            path = await save_upload_to_tmp(f, tmpdir)
            saved_paths.append(path)

        # Prepare tasks
        tasks = []
        for p in saved_paths:
            # determine output filename
            base = os.path.basename(p)
            if base.endswith('.pfc'):
                outfn = base[:-4]
            else:
                outfn = base + '.dec'
            outfile = os.path.join(outdir, outfn)
            tasks.append((p, outfile, password, chunk_workers))

        # Run file-level parallelism in process pool
        with ProcessPoolExecutor(max_workers=file_workers) as pool:
            futures = {pool.submit(_process_decrypt_task, t): t for t in tasks}
            for fut in as_completed(futures):
                try:
                    outpath = fut.result()
                    processed_outputs.append(outpath)
                except Exception as e:
                    traceback.print_exc()
                    if background_tasks:
                        background_tasks.add_task(cleanup_dir, tmpdir)
                        background_tasks.add_task(cleanup_dir, outdir)
                    raise HTTPException(status_code=500, detail=f'Decryption failed: {e}')

        # Return single file directly or zip multiple
        if len(processed_outputs) == 1:
            if background_tasks:
                background_tasks.add_task(cleanup_dir, tmpdir)
                background_tasks.add_task(cleanup_dir, outdir)
            return FileResponse(processed_outputs[0],
                                media_type='application/octet-stream',
                                filename=os.path.basename(processed_outputs[0]))
        else:
            zip_base = os.path.join(outdir, 'pfc_results')
            zip_path = zip_base + '.zip'
            shutil.make_archive(zip_base, 'zip', outdir)
            if background_tasks:
                background_tasks.add_task(cleanup_dir, tmpdir)
                background_tasks.add_task(cleanup_dir, outdir)
            return FileResponse(zip_path, media_type='application/zip', filename='pfc_results.zip')

    finally:
        # CHANGED: cleanup handled via BackgroundTasks
        pass

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('backend:app', host='0.0.0.0', port=8000, reload=True)