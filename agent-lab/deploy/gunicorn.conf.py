"""Conservative single-process WSGI limits for the Supabase Free-tier audit service.

Bind only to localhost; terminate TLS and enforce edge request limits at a trusted proxy.
"""
bind = "127.0.0.1:8080"
workers = 1
worker_class = "sync"
threads = 1
timeout = 10
graceful_timeout = 5
keepalive = 2
limit_request_line = 4096
limit_request_fields = 32
limit_request_field_size = 8190
forwarded_allow_ips = "127.0.0.1"
accesslog = "-"
errorlog = "-"
loglevel = "info"
