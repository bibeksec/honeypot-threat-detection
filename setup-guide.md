# Setup guide

## 0. Ground rules
- Use a **dedicated, disposable VPS** (1-2 vCPU, 4 GB RAM is enough). Never your home network.
- Read your provider's terms: some restrict honeypots or require notice.
- Store nothing sensitive on the box. Snapshot it before exposing it.

## 1. Harden real SSH first
```bash
# move admin SSH off port 22 BEFORE the honeypot takes 22
sudo sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh      # keep your current session open and test a NEW one on 2200
sudo ufw allow 2200/tcp && sudo ufw allow 22/tcp && sudo ufw enable
```

## 2. Deploy
```bash
git clone <your-repo> && cd honeypot-threat-detection-lab
cp .env.example .env            # set HONEYPOT_SSH_PORT=22 and API keys
sudo sysctl -w vm.max_map_count=262144   # Elasticsearch requirement
docker compose up -d
docker compose ps
```

## 3. Verify
```bash
ssh -p 22 root@<vps-ip>         # from another machine: any password should "work" in Cowrie
docker compose logs -f filebeat
curl -s 127.0.0.1:9200/_cat/indices?v   # expect a cowrie-* index
```

## 4. Kibana
Tunnel (`ssh -p 2200 -L 5601:127.0.0.1:5601 you@vps`), open http://localhost:5601,
create a data view for `cowrie-*`, then build: attacks over time, top source countries
(via enrichment), top usernames/passwords, top commands, malware download URLs.
Export via Stack Management > Saved Objects into `dashboards/kibana-export.ndjson`.

## 5. Run detections and response
```bash
docker compose cp cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ./data/cowrie.json
python detections/engine.py --logs data/cowrie.json --json \
  | python automation/enrich_ip.py \
  | python automation/auto_block.py \
  | python automation/alert_bot.py
```
Schedule with cron every 5 minutes once you trust the policy; add `--apply` to the
blocker only after reviewing dry-run output for a few days.

## 6. Collect, then write up
Run 2-4 weeks, then fill in `docs/findings-report.md`.
