import os, tempfile
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import pikepdf

app=FastAPI(title="PDF Unlocker Pro API")
origins=os.getenv("FRONTEND_ORIGIN","*")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in origins.split(",")], allow_credentials=False, allow_methods=["POST","GET"], allow_headers=["*"])
MAX_BYTES=20*1024*1024

@app.get("/")
def health():
    return {"status":"ok","service":"PDF Unlocker Pro API"}

async def save_pdf(upload, folder):
    if not (upload.filename or "").lower().endswith(".pdf"):
        raise HTTPException(400,"Please upload a PDF file.")
    data=await upload.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise HTTPException(413,"PDF must be 20 MB or smaller.")
    if not data.startswith(b"%PDF-"): raise HTTPException(400,"Invalid PDF file.")
    p=Path(folder)/"input.pdf"; p.write_bytes(data); return p

@app.post("/unlock")
async def unlock(file: UploadFile=File(...), password: str=Form(...)):
    with tempfile.TemporaryDirectory(prefix="pdfunlock_") as d:
        src=await save_pdf(file,d); out=Path(d)/"unlocked.pdf"
        try:
            with pikepdf.open(src,password=password) as pdf: pdf.save(out)
        except pikepdf.PasswordError: raise HTTPException(401,"Incorrect password.")
        except Exception: raise HTTPException(400,"Could not process this PDF.")
        data=out.read_bytes()
    return Response(data,media_type="application/pdf",headers={"Content-Disposition":'attachment; filename="unlocked.pdf"',"Cache-Control":"no-store"})

@app.post("/recover")
async def recover(file: UploadFile=File(...), candidates: str=Form(...)):
    words=[x.strip() for x in candidates.splitlines() if x.strip()]
    if not words: raise HTTPException(400,"Enter candidate passwords, one per line.")
    if len(words)>100: raise HTTPException(400,"Maximum 100 candidate passwords per request.")
    with tempfile.TemporaryDirectory(prefix="pdfrecover_") as d:
        src=await save_pdf(file,d)
        for word in words:
            try:
                with pikepdf.open(src,password=word): return {"found":True,"password":word,"message":"Matching candidate found."}
            except pikepdf.PasswordError: pass
            except Exception: raise HTTPException(400,"Could not process this PDF.")
    return {"found":False,"message":"None of the supplied candidate passwords matched."}
