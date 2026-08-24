with open("scripts/gen_constants.py", "r") as f:
    lines = f.readlines()

idx_rnte = -1
for i, line in enumerate(lines):
    if "emit_rnte_vectors(a.out)" in line:
        idx_rnte = i
        break
lines.insert(idx_rnte + 1, "    emit_poseidon(a.out)\n    emit_poseidon_goldens(a.out)\n")

idx_main = -1
for i, line in enumerate(lines):
    if line.startswith("def main():"):
        idx_main = i
        break

with open("scripts/partA.py", "r") as f:
    partA = f.read()

lines.insert(idx_main, partA + "\n")

with open("scripts/gen_constants.py", "w") as f:
    f.writelines(lines)
