import subprocess
import os


def calculate(expr):
    return eval(expr)


def execute_code(code):
    exec(code)


def run_command(cmd):
    return os.system(cmd)


def pipe_command(cmd):
    return os.popen(cmd)


def run_subprocess(cmd):
    return subprocess.call(cmd, shell=True)


def run_subprocess_run(cmd):
    return subprocess.run(cmd, shell=True)


def run_subprocess_popen(cmd):
    return subprocess.Popen(cmd, shell=True)


def dynamic_compile(src):
    return compile(src, "<string>", "exec")
