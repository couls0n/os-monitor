import pandas as pd

from experiments.split_utils import prepare_split_frame, time_split_boundary


def test_prepare_split_frame_drops_overlapping_windows_by_default():
    frame = pd.DataFrame(
        {
            "session_index": list(range(6)),
            "start_ts": [0.0, 0.25, 0.5, 0.75, 1.0, 1.25],
            "window_ms": [500] * 6,
            "stride_ms": [250] * 6,
            "label": ["a"] * 6,
        }
    )

    prepared, step = prepare_split_frame(frame, allow_overlap_windows=False, sampling_phase=0)

    assert step == 2
    assert prepared["session_index"].tolist() == [0, 2, 4]


def test_time_split_boundary_keeps_non_empty_train_and_test():
    assert time_split_boundary(10, 0.3) == 7
    assert time_split_boundary(2, 0.9) == 1
