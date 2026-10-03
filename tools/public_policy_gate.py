from pathlib import Path
import sys
required=["README.md","LICENSE","NOTICE","pyproject.toml",".gitignore"]
missing=[p for p in required if not Path(p).is_file()]
errors=[]
if missing: errors.append("missing required public files: "+", ".join(missing))
project=Path("pyproject.toml").read_text(encoding="utf-8") if Path("pyproject.toml").exists() else ""
if 'requires-python = ">=3.13"' not in project: errors.append("Python >=3.13 baseline missing")
if errors:
 print("POLICY FAIL"); print("\n".join(errors)); sys.exit(1)
print("POLICY PASS")
