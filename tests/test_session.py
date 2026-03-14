"""Unit tests for SessionStore — sliding window of recent tool calls."""

from agentgate.session import SessionEntry, SessionStore


def test_empty_store():
    store = SessionStore()
    assert len(store) == 0
    assert store.recent() == []


def test_record_request():
    store = SessionStore()
    entry = store.record_request("read_file", {"path": "/etc/passwd"})
    assert len(store) == 1
    assert entry.tool_name == "read_file"
    assert entry.arguments == {"path": "/etc/passwd"}
    assert entry.response_text is None


def test_record_response():
    store = SessionStore()
    entry = store.record_request("read_file", {"path": "/tmp/x"})
    store.record_response(entry, '{"content": "hello"}')
    assert entry.response_text == '{"content": "hello"}'


def test_recent_ordering():
    store = SessionStore()
    store.record_request("tool_a", {})
    store.record_request("tool_b", {})
    store.record_request("tool_c", {})
    names = [e.tool_name for e in store.recent()]
    assert names == ["tool_a", "tool_b", "tool_c"]


def test_recent_n():
    store = SessionStore()
    for i in range(5):
        store.record_request(f"tool_{i}", {})
    result = store.recent(3)
    assert len(result) == 3
    assert [e.tool_name for e in result] == ["tool_2", "tool_3", "tool_4"]


def test_recent_n_larger_than_store():
    store = SessionStore()
    for i in range(3):
        store.record_request(f"tool_{i}", {})
    result = store.recent(100)
    assert len(result) == 3


def test_max_size_eviction():
    store = SessionStore(max_size=3)
    store.record_request("tool_0", {})
    store.record_request("tool_1", {})
    store.record_request("tool_2", {})
    store.record_request("tool_3", {})
    assert len(store) == 3
    names = [e.tool_name for e in store.recent()]
    assert names == ["tool_1", "tool_2", "tool_3"]


def test_clear():
    store = SessionStore()
    store.record_request("tool_a", {})
    store.record_request("tool_b", {})
    store.clear()
    assert len(store) == 0
    assert store.recent() == []


def test_timestamp_monotonic():
    store = SessionStore()
    for i in range(3):
        store.record_request(f"tool_{i}", {})
    entries = store.recent()
    for i in range(len(entries) - 1):
        assert entries[i].timestamp <= entries[i + 1].timestamp


def test_response_after_eviction():
    store = SessionStore(max_size=2)
    first = store.record_request("tool_0", {})
    store.record_request("tool_1", {})
    store.record_request("tool_2", {})
    # first has been evicted from deque, but record_response on it should not crash
    store.record_response(first, "evicted response")
    assert first.response_text == "evicted response"


def test_record_request_returns_entry():
    store = SessionStore()
    entry = store.record_request("echo_tool", {"msg": "hi"})
    assert isinstance(entry, SessionEntry)
    assert entry.tool_name == "echo_tool"
    assert entry.arguments == {"msg": "hi"}
    assert entry.response_text is None
    assert entry.timestamp > 0


def test_default_max_size():
    store = SessionStore()
    for i in range(51):
        store.record_request(f"tool_{i}", {})
    assert len(store) == 50
