import pytest

# Sample minimal test data generation

def minimal_test_data():
    return [
        {'input': 'data1', 'expected': 'result1'},
        {'input': 'data2', 'expected': 'result2'},
    ]

@pytest.fixture
def test_data():
    return minimal_test_data()