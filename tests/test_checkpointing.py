import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.checkpointing import (
    CheckpointManager,
    checkpointed_map,
    iter_with_checkpoint,
)


def test_checkpoint_manager_marks_and_persists(tmp_path):
    ckpt = CheckpointManager(tmp_path, "op1")
    assert not ckpt.is_done("item_a")
    ckpt.mark_done("item_a")
    assert ckpt.is_done("item_a")

    # Simulate a fresh process by constructing a new manager over the same dir.
    ckpt2 = CheckpointManager(tmp_path, "op1")
    assert ckpt2.is_done("item_a")
    assert not ckpt2.is_done("item_b")


def test_checkpoint_survives_truncated_final_line(tmp_path):
    ckpt = CheckpointManager(tmp_path, "op2")
    ckpt.mark_done("item_a")
    # Simulate a crash mid-write: append a truncated, invalid JSON line.
    with open(ckpt.ledger_path, "a") as f:
        f.write('{"item_id": "item_b", "stat')  # deliberately truncated

    ckpt2 = CheckpointManager(tmp_path, "op2")
    assert ckpt2.is_done("item_a")
    assert not ckpt2.is_done("item_b")  # truncated record correctly ignored


def test_checkpointed_map_resumes_without_reprocessing(tmp_path):
    processed_log = []

    def process_fn(item):
        processed_log.append(item)
        return {"result": item * 2}

    results = {}

    def on_result(item, result):
        results[item] = result["result"]

    items = [1, 2, 3]
    newly, already = checkpointed_map(
        items,
        item_id_fn=lambda x: str(x),
        process_fn=process_fn,
        checkpoint_dir=tmp_path,
        operation_name="map_test",
        on_result=on_result,
    )
    assert newly == 3
    assert already == 0
    assert results == {1: 2, 2: 4, 3: 6}

    # "Resume": rerun with the same checkpoint dir; nothing should reprocess.
    processed_log.clear()
    results.clear()
    newly2, already2 = checkpointed_map(
        items,
        item_id_fn=lambda x: str(x),
        process_fn=process_fn,
        checkpoint_dir=tmp_path,
        operation_name="map_test",
        on_result=on_result,
    )
    assert newly2 == 0
    assert already2 == 3
    assert processed_log == []  # process_fn never called again
    assert results == {}  # on_result never called for already-done items


def test_iter_with_checkpoint_skips_completed(tmp_path):
    ckpt = CheckpointManager(tmp_path, "iter_op")
    ckpt.mark_done("b")

    remaining = list(
        iter_with_checkpoint(
            ["a", "b", "c"],
            item_id_fn=lambda x: x,
            checkpoint_dir=tmp_path,
            operation_name="iter_op",
        )
    )
    assert remaining == ["a", "c"]
