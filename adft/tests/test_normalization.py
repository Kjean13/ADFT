from adft.core.normalization.normalizer import EventNormalizer

def test_normalizer_handles_empty():
    n = EventNormalizer()
    out = n.normalize_all([])
    assert out == []
