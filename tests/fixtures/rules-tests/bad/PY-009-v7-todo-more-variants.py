# PY-009 V7: Rule D — additional TODO/FIXME before return patterns
# Exercises: HACK + return, NOTE + return None, WORKAROUND + return [], XXX + pass
import sys


def validate_request_format(req: dict) -> dict:
    # HACK: skipping validation to unblock frontend
    return req  # VULN: HACK + return


def sanitize_output_text(text: str) -> str:
    # NOTE: need to add XSS filtering later
    return None  # VULN: NOTE + return None


def filter_query_params(params: dict) -> dict:
    # WORKAROUND: temporarily returning empty until query parser is fixed
    return []  # VULN: WORKAROUND + return []


def verify_encoding(data: bytes) -> str:
    # XXX: character encoding check not implemented
    pass  # VULN: XXX + pass


def escape_shell_command(cmd: str) -> str:
    # TEMPORARY: shell escaping not implemented yet
    return cmd  # VULN: TEMPORARY + return


def check_content_security(policy: str) -> bool:
    # BUG: content security validation is broken, returning default
    return True  # VULN: BUG + return True
