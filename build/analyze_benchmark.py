#!/usr/bin/env python3
"""Analyze MCP benchmark logs and project 5-tool / 3-tool performance.

Usage:
    python3 build/analyze_benchmark.py data/benchmark/calls.jsonl [annotations.yaml]
"""
import collections
import json
import sys
from datetime import datetime

TOOL_MAP_5 = {
    "search_skill": "search", "search_dicts": "search",
    "search_payload": "search", "search_tools": "search",
    "list_skills": "list", "list_dicts": "list",
    "list_payloads": "list", "list_tools": "list",
    "get_skill": "get_skill", "get_dict": "get_file",
    "get_payload": "get_file", "get_tool": "get_tool",
}

TOOL_MAP_3 = {
    "search_skill": "search", "search_dicts": "search",
    "search_payload": "search", "search_tools": "search",
    "list_skills": "search", "list_dicts": "search",
    "list_payloads": "search", "list_tools": "search",
    "get_skill": "get", "get_dict": "get_file",
    "get_payload": "get_file", "get_tool": "get",
}

MERGE_WINDOW_SEC = 30


def load_records(path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def extract_query(input_data):
    """Extract query string from input JSON."""
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    return input_data.get("query", "")


def count_redundant_searches(calls):
    """Count searches where the same query hit multiple types within MERGE_WINDOW_SEC."""
    search_calls = [c for c in calls if "search" in c["tool"] or "list" in c["tool"]]
    if not search_calls:
        return 0

    groups = collections.defaultdict(list)
    for c in search_calls:
        q = extract_query(c["input"])
        groups[q].append(c)

    redundant = 0
    for q, group in groups.items():
        if len(group) <= 1:
            continue
        group.sort(key=lambda c: c["ts"])
        first_ts = datetime.fromisoformat(group[0]["ts"].replace("Z", "+00:00"))
        for c in group[1:]:
            ts = datetime.fromisoformat(c["ts"].replace("Z", "+00:00"))
            if (ts - first_ts).total_seconds() <= MERGE_WINDOW_SEC:
                redundant += 1
    return redundant


def project_calls(calls, tool_map):
    """Project how many calls the scenario would need with a simplified tool set."""
    search_calls = [c for c in calls if "search" in c["tool"] or "list" in c["tool"]]
    get_calls = [c for c in calls if c["tool"].startswith("get_")]

    # Merge searches: same query within window -> 1 call
    search_groups = collections.defaultdict(list)
    for c in search_calls:
        q = extract_query(c["input"])
        mapped = tool_map[c["tool"]]
        search_groups[(q, mapped)].append(c)

    merged_search_count = 0
    for (q, mapped), group in search_groups.items():
        group.sort(key=lambda c: c["ts"])
        first_ts = datetime.fromisoformat(group[0]["ts"].replace("Z", "+00:00"))
        cluster = 1
        for c in group[1:]:
            ts = datetime.fromisoformat(c["ts"].replace("Z", "+00:00"))
            if (ts - first_ts).total_seconds() > MERGE_WINDOW_SEC:
                cluster += 1
                first_ts = ts
        merged_search_count += cluster

    # Get calls: count stays same (just tool names change)
    return merged_search_count + len(get_calls)


def analyze_scenario(name, calls):
    """Analyze a single scenario."""
    search_calls = [c for c in calls if "search" in c["tool"] or "list" in c["tool"]]
    get_calls = [c for c in calls if c["tool"].startswith("get_")]
    total = len(calls)
    redundant = count_redundant_searches(calls)
    wrong = sum(1 for c in calls if c.get("response_items", 1) == 0)
    total_bytes = sum(c.get("response_bytes", 0) for c in calls)
    tools_used = sorted(set(c["tool"] for c in calls))

    proj5 = project_calls(calls, TOOL_MAP_5)
    proj3 = project_calls(calls, TOOL_MAP_3)

    pct5 = (1 - proj5 / total) * 100 if total else 0
    pct3 = (1 - proj3 / total) * 100 if total else 0

    print(f"\n{'=' * 60}")
    print(f"Scenario: {name} ({len(calls)} calls)")
    print(f"{'=' * 60}")
    print(f"\nBaseline (12 tools):")
    print(f"  total_calls:          {total}")
    print(f"  search_calls:         {len(search_calls)}  ({', '.join(c['tool'] for c in search_calls)})")
    print(f"  get_calls:            {len(get_calls)}  ({', '.join(c['tool'] for c in get_calls)})")
    print(f"  redundant_searches:   {redundant}")
    print(f"  wrong_tool_calls:     {wrong}")
    print(f"  total_response_bytes: {total_bytes}")
    print(f"  tools_used:           {', '.join(tools_used)}")
    print(f"\nProjected (5 tools):    {proj5} calls ({pct5:+.0f}%)")
    print(f"Projected (3 tools):    {proj3} calls ({pct3:+.0f}%)")

    return {
        "total": total, "search": len(search_calls), "get": len(get_calls),
        "redundant": redundant, "wrong": wrong, "bytes": total_bytes,
        "proj5": proj5, "proj3": proj3,
    }


def print_summary(scenarios):
    """Print aggregate summary."""
    n = len(scenarios)
    if n == 0:
        return

    print(f"\n{'=' * 60}")
    print(f"Summary Across {n} Scenarios")
    print(f"{'=' * 60}")

    avg = lambda key: sum(s[key] for s in scenarios.values()) / n

    print(f"\n{'':24s} {'12-tool':>10s} {'5-tool':>10s} {'3-tool':>10s}")
    print(f"  {'avg_total_calls':22s} {avg('total'):10.1f} {avg('proj5'):10.1f} {avg('proj3'):10.1f}")
    print(f"  {'avg_search_calls':22s} {avg('search'):10.1f} {'—':>10s} {'—':>10s}")
    print(f"  {'avg_redundant':22s} {avg('redundant'):10.1f} {'0':>10s} {'0':>10s}")
    print(f"  {'avg_wrong_calls':22s} {avg('wrong'):10.1f} {'—':>10s} {'—':>10s}")

    total_12 = sum(s["total"] for s in scenarios.values())
    total_5 = sum(s["proj5"] for s in scenarios.values())
    total_3 = sum(s["proj3"] for s in scenarios.values())

    if total_12 > 0:
        print(f"\n  calls_saved (5-tool): {(1 - total_5/total_12)*100:.0f}%")
        print(f"  calls_saved (3-tool): {(1 - total_3/total_12)*100:.0f}%")

    print(f"\n  tool_description_tokens (est): 12-tool ~1000 / 5-tool ~400 / 3-tool ~250")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <calls.jsonl>", file=sys.stderr)
        sys.exit(1)

    records = load_records(sys.argv[1])
    by_scenario = collections.defaultdict(list)
    for r in records:
        by_scenario[r["scenario"]].append(r)

    results = {}
    for name in sorted(by_scenario):
        results[name] = analyze_scenario(name, by_scenario[name])

    print_summary(results)


if __name__ == "__main__":
    main()
