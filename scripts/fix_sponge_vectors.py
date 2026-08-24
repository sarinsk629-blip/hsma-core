with open("scripts/gen_constants.py", "r") as f:
    c = f.read()

bad_logic = "es = [rng.randrange(p) for _ in els]"

good_logic = """es = []
        for k_idx in range(len(els)):
            if k_idx < 2:
                es.append(rng.randrange(p))
            else:
                es.append(k_idx)"""

c = c.replace(bad_logic, good_logic)

with open("scripts/gen_constants.py", "w") as f:
    f.write(c)
