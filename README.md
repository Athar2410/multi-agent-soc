## Setup

1. `pip install -r requirements.txt`
2. Download MITRE ATT&CK data:
   `curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -o mitre_attack.json`
3. Add your RF model: copy `rf_multiclass.pkl` from your AgentSIEM project
4. Ingest logs: `python ingestor.py`
5. Run pipeline: `python pipeline_runner.py`