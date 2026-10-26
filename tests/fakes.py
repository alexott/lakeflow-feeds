from feedkit.sinks import SinkError


class MemorySink:
    def __init__(self, fail_on_call: int | None = None):
        self.writes: list[tuple[str, list[dict]]] = []
        self.calls = 0
        self.fail_on_call = fail_on_call

    def write(self, table, rows, *, fetch_id, day):
        self.calls += 1
        if self.fail_on_call == self.calls:
            raise SinkError("injected failure")
        self.writes.append((table, list(rows)))


class FakeFetcher:
    def __init__(self, *results):
        self.results, self.calls = list(results), 0

    def __call__(self, fetch, change_detection, state):
        self.calls += 1
        return self.results.pop(0)


class FakeContext:
    def __init__(self):
        self.values = {}

    def set_task_value(self, key, value):
        self.values[key] = value

    def get_task_value(self, key, default=None):
        return self.values.get(key, default)
