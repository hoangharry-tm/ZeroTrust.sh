import subprocess
def run_job(job_name):
    result = subprocess.run(f"process_job {job_name}", shell=True, capture_output=True)
    return result.stdout.decode()
