from monitoring.event_schema import normalize_event, sort_events


def test_sort_prefers_monotonic_timeline_over_capture_wall_time():
    later_capture = normalize_event(
        {
            "source": "file",
            "event": "write",
            "pid": 10,
            "ts_ns": 2_000_000_000,
            "timestamp": "2026-03-30T00:00:05+00:00",
        }
    )
    earlier_capture = normalize_event(
        {
            "source": "file",
            "event": "write",
            "pid": 10,
            "ts_ns": 1_000_000_000,
            "timestamp": "2026-03-30T00:00:10+00:00",
        }
    )

    ordered = sort_events([later_capture, earlier_capture])

    assert [event["ts_ns"] for event in ordered] == [1_000_000_000, 2_000_000_000]
