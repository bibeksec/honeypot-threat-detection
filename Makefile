.PHONY: test demo rules-doc up down
test:
	python -m unittest discover -s tests -v

demo:
	python detections/engine.py --rules detections/rules --logs detections/tests/sample_cowrie.jsonl --json \
	  | python automation/enrich_ip.py \
	  | python automation/auto_block.py \
	  | python automation/alert_bot.py

rules-doc:
	python detections/engine.py --rules detections/rules --list-rules > detections/attack-mapping.md

up:
	docker compose up -d
down:
	docker compose down
