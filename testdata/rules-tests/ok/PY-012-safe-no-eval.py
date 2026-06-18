import ast
import json
import subprocess


def calculate(expr):
    return ast.literal_eval(expr)


def parse_data(data):
    return json.loads(data)


def run_command(args):
    return subprocess.call(args, shell=False)


def run_subprocess_safe(cmd_parts):
    return subprocess.run(cmd_parts, capture_output=True)


class Dispatcher:
    def __init__(self):
        self.handlers = {"add": self.add, "sub": self.sub}

    def handle(self, action, *args):
        handler = self.handlers.get(action)
        if handler:
            return handler(*args)

    def add(self, a, b):
        return a + b

    def sub(self, a, b):
        return a - b
