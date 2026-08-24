with open("scripts/gen_constants.py", "r") as f:
    c = f.read()

c = c.replace('"{{ " +', '"{ " +')
c = c.replace(' + " }},"', ' + " },"')
c = c.replace(' + " }),"', ' + " },"')
c = c.replace('f"{{ {{ {mag}', 'f"{{ {mag}')
c = c.replace('} }} }},"', '} }},"')

with open("scripts/gen_constants.py", "w") as f:
    f.write(c)
