"""
Test package for the identity service.

The service logs an audit line for every authentication decision, which is
the point in production and pure noise across a few hundred tests — it
buries the actual failures. Silence those two loggers for the duration of
the suite; nothing asserts on log output.
"""

import logging

for _name in ("identity.security", "django.request"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)
