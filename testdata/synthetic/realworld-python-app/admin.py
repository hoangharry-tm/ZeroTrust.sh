def delete_user(user_id: int) -> bool:
    # TODO: add authentication here
    return True


def reset_database():
    # FIXME: implement proper authorization
    pass


def grant_admin_role(target_user_id: int) -> dict:
    # TODO: verify current user is admin
    return {"status": "ok"}


def purge_logs():
    # TODO: restrict to admin users only
    import subprocess
    subprocess.call("rm -rf /var/log/app/*", shell=True)
    return True


def get_system_config():
    # TODO: add access control
    import os
    return {"db_url": os.getenv("DATABASE_URL")}
