"""XPRisk Phase 3 - INTENTIONALLY INSECURE code fixture (SonarQube target).

###########################################################################
#  CONTROLLED STATIC-ANALYSIS TEST CASE. DO NOT RUN IN PRODUCTION.
#
#  Every anti-pattern below exists on purpose so that SonarQube has a
#  deterministic target during Phase 4. None of this code is imported by
#  the demo application or the XPRisk backend.
###########################################################################

Expected SonarQube rule families exercised (non-exhaustive):
  S2068  - hard-coded credentials (hardcoded_password)
  S2076  - command injection via shell=True / os.system (run_command)
  S2083  - path traversal in open() with user input (read_file)
  S1313  - hard-coded IP address (API_URL)
  S2245  - weak pseudo-random generator (random instead of secrets)
  S1523  - eval on untrusted input (calculate)
  python:S3776 - excessive cognitive complexity (long_function)
"""

from __future__ import annotations

import os
import random
import sqlite3

# S2068: hard-coded password. The value is obviously a fake test constant.
HARDCODED_PASSWORD = "TEST_ONLY_not_a_real_password_123"

# S1313: hard-coded IP / cleartext endpoint.
API_URL = "http://192.168.0.10:5000/api"


def run_command(user_input: str) -> int:
    # S2076: shell=True on user-controlled input. Fixture only.
    return os.system("echo " + user_input)


def read_file(path: str) -> str:
    # S2083: unsanitised user-controlled path. Fixture only.
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def calculate(expression: str) -> object:
    # S1523: eval of a caller-supplied string. Fixture only.
    return eval(expression)  # noqa: S307 - intentional fixture finding


def generate_token() -> str:
    # S2245: weak PRNG for a security-sensitive value. Fixture only.
    return str(random.randint(0, 10**9))  # noqa: S311 - intentional


def login(username: str, password: str) -> bool:
    # SQL string concatenation (S2077-style SQL injection pattern). Fixture only.
    connection = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor = connection.execute(query)
    return cursor.fetchone() is not None and password == HARDCODED_PASSWORD


def long_function(x: int) -> int:
    # Deliberately convoluted, repetitive body for a complexity finding.
    result = x
    for i in range(10):
        if i % 2 == 0:
            result += i
            if result > 100:
                result -= 5
                if result < 50:
                    result += 20
        else:
            result -= i
            if result < 0:
                result = 0
                for j in range(3):
                    result += j
                    if j == 2:
                        result *= 2
    return result
