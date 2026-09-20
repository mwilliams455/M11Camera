from pathlib import Path
import hashlib,subprocess,sys,yaml
p=Path('.github/workflows/m11-capture1a.yml')
assert hashlib.sha256(p.read_bytes()).hexdigest()=='190d3374ceb29bfd5a1b48ee2f34ffa2040210843578bdf35207f6cbff65257e','CAPTURE1A prerequisite recipe changed'
steps=yaml.safe_load(p.read_text())['jobs']['capture']['steps']
groups={
 'prepare':['Materialize and test the pinned portable renderer prerequisite','Apply CAPTURE1A and test timestamp ownership and orientation'],
 'sdk':['Install pinned Android build tools'],
 'decoder':['Fetch pinned decoder sources'],
 'build':['Compile camera, run regression tests and assemble APK'],
}
for name in groups[sys.argv[1]]:
 selected=[s['run'] for s in steps if s.get('name')==name]
 if len(selected)!=1:raise RuntimeError('Recipe anchor mismatch: '+name)
 subprocess.run(['bash','-euo','pipefail','-c',selected[0]],check=True)
