import json
import csv
import os
import time

class ReportExporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(os.path.dirname(os.path.abspath(self.output_dir)), exist_ok=True)
        
    def generate_filename(self, ext):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.output_dir, f"kernelguard_report_{timestamp}.{ext}")

    def export_json(self, alerts, modules):
        filename = self.generate_filename("json")
        data = {
            "alerts": [a.__dict__ for a in alerts],
            "modules": [m.__dict__ for m in modules]
        }
        with open(filename, 'w') as f:
            json.dump(data, f, default=str, indent=4)
        return filename

    def export_csv(self, alerts):
        filename = self.generate_filename("csv")
        with open(filename, 'w', newline='') as f:
            if not alerts:
                return filename
            writer = csv.DictWriter(f, fieldnames=alerts[0].__dict__.keys())
            writer.writeheader()
            for alert in alerts:
                row = alert.__dict__.copy()
                row['severity'] = row['severity'].name
                writer.writerow(row)
        return filename

    def export_html(self, alerts, modules, is_mock=True):
        filename = self.generate_filename("html")
        html = f"""
        <html>
        <head><title>KernelGuard Report</title></head>
        <body>
        <h1>KernelGuard Security Report</h1>
        <p>Generated: {time.ctime()}</p>
        <p>Mode: {'MOCK/DEMO' if is_mock else 'LIVE'}</p>
        
        <h2>Alerts ({len(alerts)})</h2>
        <table border="1">
            <tr><th>Time</th><th>Severity</th><th>Category</th><th>Target</th><th>Score</th><th>Explanation</th></tr>
            {"".join(f"<tr><td>{time.ctime(a.timestamp)}</td><td>{a.severity.name}</td><td>{a.category}</td><td>{a.target}</td><td>{a.risk_score}</td><td>{a.explanation}</td></tr>" for a in alerts)}
        </table>
        
        <h2>Modules ({len(modules)})</h2>
        <table border="1">
            <tr><th>Name</th><th>Size</th><th>State</th><th>Signature</th><th>Trusted</th></tr>
            {"".join(f"<tr><td>{m.name}</td><td>{m.size}</td><td>{m.state}</td><td>{m.signature_status}</td><td>{m.trusted}</td></tr>" for m in modules)}
        </table>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(html)
        return filename
