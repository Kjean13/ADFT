from adft.correlation.engine import CorrelationEngine

def test_correlation_on_empty_detections():
    eng = CorrelationEngine()
    out = eng.correlate([])
    assert isinstance(out, list)
