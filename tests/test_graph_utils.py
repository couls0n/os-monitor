from features.graph_utils import build_provenance_graph


def test_process_instances_do_not_create_orphan_node_on_first_fork():
    graph = build_provenance_graph(
        [
            {
                "source": "process",
                "action": "fork",
                "event_key": "process.fork",
                "pid": 10,
                "ppid": 1,
                "comm": "child",
                "ts_ns": 1_000_000_000,
                "timeline_ts": 1.0,
                "timestamp": "2026-03-30T00:00:00+00:00",
            },
            {
                "source": "process",
                "action": "exec",
                "event_key": "process.exec",
                "pid": 10,
                "ppid": 1,
                "comm": "child",
                "ts_ns": 2_000_000_000,
                "timeline_ts": 2.0,
                "timestamp": "2026-03-30T00:00:01+00:00",
            },
        ]
    )

    process_nodes = [
        node_id
        for node_id, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "process"
    ]
    assert len(process_nodes) == 2
