from adft.detection.engine import DetectionEngine

def test_detection_on_empty_events():
    eng = DetectionEngine()
    out = eng.run([])
    assert isinstance(out, list)
