#!/usr/bin/env python3
"""Deterministic benign PDF corpus for the EPHEM converter benchmark.
Usage: python3 -I gen_corpus.py OUTDIR   -> writes 50 PDFs + MANIFEST.sha256
Stdlib only. Same script => same bytes on any machine."""
import hashlib, os, sys
def pdf(text):
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = bytearray(b"%PDF-1.4\n"); offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs: out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    return bytes(out)
d = sys.argv[1]; os.makedirs(d, exist_ok=True); lines = []
for i in range(50):
    name = f"doc{i:02d}.pdf"; b = pdf(f"EPHEM benchmark document {i:02d} marker-free benign text")
    open(os.path.join(d, name), "wb").write(b)
    lines.append(f"{hashlib.sha256(b).hexdigest()}  {name}")
open(os.path.join(d, "MANIFEST.sha256"), "w").write("\n".join(lines) + "\n")
print(hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest())
