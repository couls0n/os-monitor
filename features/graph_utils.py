#!/usr/bin/env python3
"""Build multi-dimensional provenance graphs from normalized session events."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Tuple

import networkx as nx

from monitoring.event_schema import normalize_event, sort_events


def _ensure_node(
    graph: nx.MultiDiGraph,
    node_id: str,
    node_type: str,
    label: str,
    **attrs: Any,
) -> str:
    """Create or update a graph node."""
    if not graph.has_node(node_id):
        graph.add_node(node_id, node_type=node_type, label=label, **attrs)
    else:
        graph.nodes[node_id].update({key: value for key, value in attrs.items() if value not in ("", None)})
    return node_id


def _process_node_id(pid: int, create_key: str) -> str:
    return f"proc:{pid}:{create_key}"


def _create_process_instance(
    graph: nx.MultiDiGraph,
    process_instances: Dict[int, str],
    process_birth_index: Counter[int],
    pid: int,
    event: Dict[str, Any],
) -> str:
    create_key = str(event.get("ts_ns") or event.get("timestamp") or process_birth_index[pid])
    process_birth_index[pid] += 1
    process_instances[pid] = _process_node_id(pid, create_key)
    return _ensure_node(
        graph,
        process_instances[pid],
        "process",
        event.get("comm") or f"pid:{pid}",
        pid=pid,
        comm=event.get("comm") or "",
    )


def build_provenance_graph(events: Iterable[Dict[str, Any]]) -> nx.MultiDiGraph:
    """Build a multi-dimensional provenance graph for one session."""
    normalized = []
    for event in events:
        normalized.append(event if event.get("event_key") else normalize_event(event))
    normalized = sort_events(normalized)

    graph = nx.MultiDiGraph()
    process_instances: Dict[int, str] = {}
    process_birth_index: Counter[int] = Counter()
    last_event_ts_by_pid: Dict[int, int] = {}

    for event in normalized:
        pid = event.get("pid")
        pid_node = None
        source = event.get("source")
        action = event.get("action")
        event_key = event.get("event_key") or f"{source}.{action}"
        current_ts_ns = int(event.get("ts_ns") or 0)

        if pid is not None:
            should_rotate_instance = False
            if pid not in process_instances:
                should_rotate_instance = True
            elif source == "process" and action == "exec":
                should_rotate_instance = True
            elif source == "process" and action == "fork" and process_instances.get(pid):
                should_rotate_instance = False

            if should_rotate_instance:
                pid_node = _create_process_instance(
                    graph,
                    process_instances,
                    process_birth_index,
                    int(pid),
                    event,
                )
            else:
                pid_node = _ensure_node(
                    graph,
                    process_instances[int(pid)],
                    "process",
                    event.get("comm") or f"pid:{pid}",
                    pid=pid,
                    comm=event.get("comm") or "",
                )

        delta_ns = 0
        if pid is not None and current_ts_ns > 0:
            previous_ts_ns = last_event_ts_by_pid.get(int(pid))
            if previous_ts_ns is not None and current_ts_ns >= previous_ts_ns:
                delta_ns = current_ts_ns - previous_ts_ns
            last_event_ts_by_pid[int(pid)] = current_ts_ns

        edge_attrs = {
            "action": action,
            "source": source,
            "event_key": event_key,
            "timestamp": event.get("timestamp"),
            "ts_ns": event.get("ts_ns"),
            "timeline_ts": event.get("timeline_ts"),
            "delta_ns": delta_ns,
        }

        if source == "process" and pid_node is not None:
            ppid = event.get("ppid")
            if ppid is not None and int(ppid) in process_instances:
                parent_node = process_instances[int(ppid)]
                graph.add_edge(parent_node, pid_node, **edge_attrs, relation="process.lineage")
            continue

        if pid_node is None:
            continue

        if source == "file":
            file_path = event.get("file_path")
            if file_path:
                file_node = _ensure_node(graph, f"file:{file_path}", "file", file_path, path=file_path)
                graph.add_edge(
                    pid_node,
                    file_node,
                    **edge_attrs,
                    relation="file.access",
                    write_bytes=event.get("write_bytes", 0),
                )
            if action == "rename" and event.get("file_new_path"):
                new_path = event["file_new_path"]
                new_node = _ensure_node(graph, f"file:{new_path}", "file", new_path, path=new_path)
                if file_path:
                    graph.add_edge(f"file:{file_path}", new_node, **edge_attrs, relation="rename_to")
                graph.add_edge(pid_node, new_node, **edge_attrs, relation="file.access")
            continue

        if source == "net" and event.get("remote_ip"):
            remote_ip = event["remote_ip"]
            remote_port = event.get("remote_port") or 0
            net_label = f"{remote_ip}:{remote_port}"
            net_node = _ensure_node(
                graph,
                f"ip:{remote_ip}:{remote_port}",
                "network",
                net_label,
                ip=remote_ip,
                port=remote_port,
            )
            graph.add_edge(pid_node, net_node, **edge_attrs, relation="net.connect")
            continue

        if source == "dns" and event.get("dns_host"):
            host = event["dns_host"]
            dns_node = _ensure_node(graph, f"dns:{host}", "dns", host, host=host)
            graph.add_edge(pid_node, dns_node, **edge_attrs, relation="dns.query")
            continue

        if source == "memory":
            mem_label = action
            memory_node = _ensure_node(
                graph,
                f"memory:{pid}:{event.get('ts_ns') or event.get('timestamp')}",
                "memory",
                mem_label,
                protection=event.get("memory_protection") or "",
                length=event.get("memory_length", 0),
            )
            graph.add_edge(pid_node, memory_node, **edge_attrs, relation=f"memory.{action}")
            if action == "vm_writev" and event.get("target_pid") is not None:
                target_pid = int(event["target_pid"])
                if target_pid not in process_instances:
                    target_node = _create_process_instance(
                        graph,
                        process_instances,
                        process_birth_index,
                        target_pid,
                        {"comm": f"pid:{target_pid}", "ts_ns": event.get("ts_ns"), "timestamp": event.get("timestamp")},
                    )
                else:
                    target_node = _ensure_node(
                        graph,
                        process_instances[target_pid],
                        "process",
                        f"pid:{target_pid}",
                        pid=target_pid,
                    )
                graph.add_edge(pid_node, target_node, **edge_attrs, relation="vm_writev_target")
            continue

        if source == "syscall":
            syscall_name = event.get("syscall_name") or action
            syscall_node = _ensure_node(
                graph,
                f"syscall:{syscall_name}",
                "syscall",
                syscall_name,
                syscall=syscall_name,
            )
            graph.add_edge(pid_node, syscall_node, **edge_attrs, relation="syscall.invoke")
            continue

        if source == "kmod" and event.get("module_name"):
            module_name = event["module_name"]
            module_node = _ensure_node(
                graph,
                f"module:{module_name}",
                "module",
                module_name,
                module=module_name,
            )
            graph.add_edge(pid_node, module_node, **edge_attrs, relation="kmod.load")

    return graph


def build_process_tree(events: Iterable[Dict[str, Any]]) -> nx.DiGraph:
    """Backward-compatible process tree view extracted from the provenance graph."""
    provenance = build_provenance_graph(events)
    tree = nx.DiGraph()

    for node_id, attrs in provenance.nodes(data=True):
        if attrs.get("node_type") == "process":
            tree.add_node(node_id, **attrs)

    for source, target, attrs in provenance.edges(data=True):
        if (
            provenance.nodes[source].get("node_type") == "process"
            and provenance.nodes[target].get("node_type") == "process"
            and attrs.get("source") == "process"
        ):
            tree.add_edge(source, target, **attrs)

    return tree
