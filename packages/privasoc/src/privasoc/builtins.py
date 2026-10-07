"""Known formats (D45 step 3): fixed VRL parsers, tried before any model is involved.

Each entry uses Vector built-ins or an anchored legacy-format regex with a fixed, tested
mapping of its output to ECS. A format counts as known only if the parser understands the
whole line; a syslog header alone (body still opaque) is not enough and goes to the LLM path.
"""

from __future__ import annotations

from dataclasses import dataclass

from privasoc.structured import _assign


def _program(
    parse: str,
    mapping: dict[str, str],
    constants: dict | None = None,
    timestamp: str | None = "timestamp",
) -> str:
    lines = [f"p = {parse}"]
    if timestamp:
        lines.append(f"if p.{timestamp} != null {{ .@timestamp = p.{timestamp} }}")
    for ecs, value in (constants or {}).items():
        lines.append(f".{ecs} = {value}")
    for i, (ecs, key) in enumerate(mapping.items()):
        lines += _assign("b", ecs, f"k{i}", expr=f'get(p, ["{key}"]) ?? null')
    return "\n".join(lines) + "\n"


WEB = {
    "user.name": "user",
    "http.request.method": "method",
    "http.response.status_code": "status",
    "http.response.body.bytes": "size",
    "user_agent.original": "agent",
}


@dataclass(frozen=True)
class Builtin:
    name: str
    vrl: str


BUILTINS = [
    Builtin(
        "apache_combined",
        _program(
            'parse_apache_log!(.message, format: "combined")',
            {
                **WEB,
                "source.ip": "host",
                "url.original": "path",
                "http.request.referrer": "referrer",
            },
            {"event.kind": '"event"', "event.category": '["web"]'},
        ),
    ),
    Builtin(
        "nginx_combined",
        _program(
            'parse_nginx_log!(.message, format: "combined")',
            {**WEB, "source.ip": "client", "http.request.referrer": "referer"},
            {"event.kind": '"event"', "event.category": '["web"]'},
        ),
    ),
    Builtin(
        "apache_common",
        _program(
            'parse_apache_log!(.message, format: "common")',
            {
                **{k: v for k, v in WEB.items() if k != "user_agent.original"},
                "source.ip": "host",
                "url.original": "path",
            },
            {"event.kind": '"event"', "event.category": '["web"]'},
        ),
    ),
    Builtin(
        "apache_access_mixed",
        "access = string!(.message)\n"
        "h = parse_regex(access, r'^(?P<vhost>\\S+):(?P<port>\\d+) "
        "(?P<access>\\S+ \\S+ \\S+ \\[.*)$') ?? {}\n"
        "if h.access != null { access = string!(h.access) }\n"
        "d = parse_regex(access, r'^(?P<base>\\S+ \\S+ \\S+ \\[[^\\]]+\\] "
        '"(?:\\\\.|[^"\\\\])*" \\d+ (?:\\d+|-)) \\d+(?P<tail>.*)$\') ?? {}\n'
        "if d.base != null { access = string!(d.base) + string!(d.tail) }\n"
        + _program(
            'parse_apache_log(access, format: "combined") ?? '
            'parse_apache_log!(access, format: "common")',
            {
                **WEB,
                "source.ip": "host",
                "url.original": "path",
                "http.request.referrer": "referrer",
            },
            {"event.kind": '"event"', "event.category": '["web"]'},
        ),
    ),
    Builtin(
        "apache_error_legacy",
        _program(
            "parse_regex!(.message, r'^\\[(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} "
            "+\\d{1,2} \\d{2}:\\d{2}:\\d{2} \\d{4})\\] "
            "\\[(?P<severity>emerg|alert|crit|error|warn|notice|info|debug)\\] "
            "(?P<message>.*)$')",
            {"log.level": "severity", "message": "message"},
            {"event.kind": '"event"', "event.category": '["web"]'},
            timestamp=None,
        )
        + '.@timestamp = parse_timestamp!(p.timestamp, format: "%a %b %d %H:%M:%S %Y")\n',
    ),
    Builtin(
        "cef",
        _program(
            "parse_cef!(.message)",
            {
                "observer.vendor": "deviceVendor",
                "observer.product": "deviceProduct",
                "observer.version": "deviceVersion",
                "event.code": "deviceEventClassId",
                "event.action": "act",
                "source.ip": "src",
                "destination.ip": "dst",
                "source.port": "spt",
                "destination.port": "dpt",
                "user.name": "suser",
                "network.transport": "proto",
                "url.original": "request",
            },
            {"event.kind": '"event"'},
            timestamp=None,
        ),
    ),
]


def detect(sandbox, lines: list[str], threshold: float = 0.9) -> tuple[Builtin, float] | None:
    """The first built-in (in priority order) that parses at least `threshold` of the lines."""
    if not lines:
        return None
    best = None
    for b in BUILTINS:
        res = sandbox.run(b.vrl, lines)
        if res.compile_error:
            continue
        rate = len(res.outputs) / len(lines)
        if rate >= threshold and (best is None or rate > best[1]):
            best = (b, rate)
    return best
