# PY-007 EDGE/SAFE: placeholder values in password-named variables
# These are template/example placeholders that the exclusion regex should catch
# Values like "changeme", "password", "secret", "example" are excluded
import os

# These should NOT fire because value matches the exclusion placeholder regex
db_password = "changeme"          # excluded: "changeme"
secret = "password"               # excluded: "password"
db_pass = "secret"                # excluded: "secret"
admin_pass = "example"            # excluded: "example"
auth_secret = "placeholder"       # excluded: "placeholder"
master_key = "your_key_here"      # excluded: starts with "your_"
private_key = "<PRIVATE_KEY>"     # excluded: looks like a template placeholder
passwd = "test"                   # excluded: "test"
password = ""                     # excluded: empty string

# Also safe: using os.getenv
db_secret = os.getenv("DB_SECRET", "fallback_val")

print("Template configuration loaded — replace all placeholders before deploying")
