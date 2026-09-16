from concurrent.futures import ThreadPoolExecutor

import pytest

from app.database import Database
from app.detection import DetectionEngine
from app.models import LogEventCreate
from scripts.generate_demo_data import seed_demo


def test_seed_is_idempotent_across_database_instances(tmp_path):
    path = tmp_path / "demo.db"
    assert seed_demo(Database(path)) == (42, 3)
    assert seed_demo(Database(path)) == (0, 0)
    assert len(Database(path).list_events()) == 42
    assert len(Database(path).list_alerts()) == 3


def test_seed_preserves_existing_events(tmp_path):
    database = Database(tmp_path / "existing.db")
    event = database.insert_event(LogEventCreate(event_type="login_success", source_ip="10.0.0.1"))
    assert seed_demo(database) == (0, 0)
    assert database.list_events() == [event]


def test_concurrent_seed_runs_only_once(tmp_path):
    path = tmp_path / "concurrent.db"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: seed_demo(Database(path)), range(2)))
    assert sorted(results) == [(0, 0), (42, 3)]
    assert len(Database(path).list_events()) == 42


def test_failed_seed_rolls_back_and_can_retry(tmp_path, monkeypatch):
    database = Database(tmp_path / "rollback.db")

    def fail_detection(self, event):
        raise RuntimeError("simulated failure")

    with monkeypatch.context() as patch:
        patch.setattr(DetectionEngine, "evaluate", fail_detection)
        with pytest.raises(RuntimeError, match="simulated failure"):
            seed_demo(database)
    assert database.list_events() == []
    assert database.list_alerts() == []
    assert seed_demo(database) == (42, 3)
