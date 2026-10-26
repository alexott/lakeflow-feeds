def parse(content: bytes, spec):
    values = [v for v in content.decode().split(",") if v]
    raw = [{"v": v} for v in values]
    return raw, [{"value": v, "observable_type": "domain"} for v in values]
