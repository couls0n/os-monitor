from dataset.prepare_dataset import build_windows


def test_build_windows_preserves_wall_clock_boundaries_from_monotonic_time():
    events = [
        {
            "source": "process",
            "event_key": "process.exec",
            "pid": 100,
            "ts_ns": 1_000_000_000,
            "timeline_ts": 1.0,
            "timestamp": "2026-03-30T00:00:00+00:00",
        },
        {
            "source": "file",
            "event_key": "file.write",
            "pid": 100,
            "ts_ns": 1_200_000_000,
            "timeline_ts": 1.2,
            "timestamp": "2026-03-30T00:00:00.200000+00:00",
        },
        {
            "source": "file",
            "event_key": "file.rename",
            "pid": 100,
            "ts_ns": 1_600_000_000,
            "timeline_ts": 1.6,
            "timestamp": "2026-03-30T00:00:00.600000+00:00",
        },
    ]

    sessions = build_windows(events, window_ms=500, stride_ms=500, min_events=1)

    assert len(sessions) == 2
    assert sessions[0]["start"] == "2026-03-30T00:00:00+00:00"
    assert sessions[0]["end"] == "2026-03-30T00:00:00.500000+00:00"
    assert sessions[0]["start_ts"] == 1774828800.0
    assert sessions[1]["start"] == "2026-03-30T00:00:00.500000+00:00"
