from adft.timeline.engine import TimelineEngine

def test_timeline_on_empty_inputs():
    eng = TimelineEngine()
    out = eng.build([], [])
    assert isinstance(out, list)
