import subprocess
def run_job(job_name: str) -> str:
    allowed = {"compress", "validate", "report"}
    if job_name not in allowed:
        raise ValueError(f"unknown job: {job_name!r}")
    result = subprocess.run(["process_job", job_name], capture_output=True, check=True)
    return result.stdout.decode()
