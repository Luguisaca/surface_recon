from pathlib import Path
import subprocess, sys
tracked=[Path(x) for x in subprocess.check_output(["git","ls-files"],text=True).splitlines()]
forbidden_exact={"AGENTS.md"}
forbidden_prefixes=(".specify/","specs/","benchmarks/")
findings=[]
for p in tracked:
 s=p.as_posix()
 if s in forbidden_exact or s.startswith(forbidden_prefixes):
  findings.append("forbidden public file: "+s)
if findings:
 print("PUBLIC SURFACE FAIL"); print("\n".join(findings)); sys.exit(1)
print(f"PUBLIC SURFACE PASS ({len(tracked)} tracked files checked)")
