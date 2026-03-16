PYTHON ?= python3

.PHONY: test smoke clean

test:
	$(PYTHON) -m pytest -q

smoke:
	$(PYTHON) main.py convert adft/datasets/demo_mixed_inputs -o /tmp/adft_convert_smoke
	$(PYTHON) main.py investigate adft/datasets/demo_mixed_inputs -o /tmp/adft_reports_smoke
	$(PYTHON) main.py summary -o /tmp/adft_reports_smoke
	$(PYTHON) main.py story -o /tmp/adft_reports_smoke
	$(PYTHON) main.py attack-chain -o /tmp/adft_reports_smoke
	$(PYTHON) main.py attack-path -o /tmp/adft_reports_smoke

clean:
	rm -rf .pytest_cache htmlcov .coverage build dist *.egg-info /tmp/adft_convert_smoke /tmp/adft_reports_smoke
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
