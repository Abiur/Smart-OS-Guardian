import sys, pathlib, os, tempfile, pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "agent" / "python-agent"))


@pytest.fixture()
def agent(tmp_path):
    os.environ["GUARDIAN_DATA_DIR"] = str(tmp_path)
    from guardian.agent import Agent
    a = Agent(db_path=tmp_path / "t.db", start_collectors=False)
    yield a
    a.stop()
