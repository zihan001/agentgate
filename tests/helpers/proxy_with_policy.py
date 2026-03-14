"""Test harness: runs StdioProxy with a policy loaded from AGENTGATE_TEST_POLICY env var."""

import asyncio
import os
import sys

from agentgate.policy import load_and_compile
from agentgate.proxy import StdioProxy

policy_path = os.environ.get("AGENTGATE_TEST_POLICY")
policy = load_and_compile(policy_path) if policy_path else None
audit_db = os.environ.get("AGENTGATE_TEST_AUDIT_DB")
server_cmd = sys.argv[1:]
proxy = StdioProxy(server_cmd, policy=policy, audit_db=audit_db)
sys.exit(asyncio.run(proxy.run()))
