import sqlite3
import json
import os
from backend.models import ProcessRecord, Alert, ComparisonResult, KernelModuleRecord, EventRecord, AlertSeverity

class Database:
    def __init__(self, db_path="data/history.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp REAL,
                severity TEXT,
                category TEXT,
                target TEXT,
                risk_score INTEGER,
                evidence TEXT,
                explanation TEXT,
                resolution_status TEXT,
                is_simulated BOOLEAN
            )
        ''')
        self.conn.commit()

    def save_alerts(self, alerts):
        cursor = self.conn.cursor()
        for alert in alerts:
            cursor.execute('''
                INSERT OR REPLACE INTO alerts 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_id, alert.timestamp, alert.severity.name,
                alert.category, alert.target, alert.risk_score,
                alert.evidence, alert.explanation, alert.resolution_status,
                alert.is_simulated
            ))
        self.conn.commit()

    def get_alerts(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        alerts = []
        for row in rows:
            alerts.append(Alert(
                alert_id=row[0],
                timestamp=row[1],
                severity=AlertSeverity[row[2]],
                category=row[3],
                target=row[4],
                risk_score=row[5],
                evidence=row[6],
                explanation=row[7],
                resolution_status=row[8],
                is_simulated=bool(row[9])
            ))
        return alerts
