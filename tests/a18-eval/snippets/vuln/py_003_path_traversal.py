import os
def read_template(name):
    path = os.path.join("/var/templates", name)
    with open(path) as f:
        return f.read()
