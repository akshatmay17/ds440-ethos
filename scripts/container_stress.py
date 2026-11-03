#!/usr/bin/env python3
"""Record real container-boundary tests. Unavailable Docker is never a pass."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=ROOT/"reports/container_isolation.json")
    args=parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output path; preserve earlier evidence")
    image=json.loads((ROOT/"config/exec.container.json").read_text())["image"]
    report={"created_at":datetime.now(timezone.utc).isoformat(),"mode":"live_docker_and_file_boundary_regressions",
            "image":image,"passed":False,"git_rev":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
            "source_sha256":{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
                ["src/runtime/container.rs","src/aci/harness.rs","src/bin/ethos.rs","tests/test_rust_container.rs","tests/test_rust_file_aliases.rs"]},
            "limitations":["Container/daemon/kernel exploits are not tested.",
                "Tests exercise disposable commands, not MCP, GUI agents or full attack benchmark semantics.",
                "Container filesystem changes are discarded; these are not host workspace mutation tests."]}
    report["source_sha256"].update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((ROOT/"src").rglob("*.rs"))})
    for relative in ["Cargo.toml","Cargo.lock","config/exec.container.json","scripts/container_stress.py"]:
        report["source_sha256"][relative]=hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
    try:
        server=subprocess.run(["docker","version","--format","{{json .Server}}"],cwd=ROOT,capture_output=True,text=True,timeout=30)
        if server.returncode:
            raise RuntimeError("Local Docker engine unavailable: "+server.stderr[:1000])
        report["docker_server"]=json.loads(server.stdout)
        inspect=subprocess.run(["docker","image","inspect",image,"--format","{{json .Id}}"],cwd=ROOT,capture_output=True,text=True,timeout=30)
        if inspect.returncode:
            raise RuntimeError("Pinned image unavailable; pull the configured digest explicitly before testing")
        report["local_image_id"]=json.loads(inspect.stdout)
        command=["cargo","test","--test","test_rust_container","--test","test_rust_file_aliases","--","--include-ignored","--test-threads=1"]
        result=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",timeout=300)
        tests=[{"name":name,"outcome":outcome} for name,outcome in re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)",result.stdout,re.MULTILINE)]
        report.update(command=command,exit_code=result.returncode,tests=tests,output=result.stdout,
                      passed=result.returncode==0 and bool(tests) and all(t["outcome"]=="ok" for t in tests))
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        report["error"]=str(error)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"passed":report["passed"],"tests":len(report.get("tests",[])),"report":str(args.output),"error":report.get("error")}))
    return 0 if report["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
