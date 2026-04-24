import pandas as pd
import json
import os
from typing import Dict

class ReportGenerator:
    """
    Analyzes classified logs and generates attack reports in multiple formats.
    """

    def __init__(self, df: pd.DataFrame):
        """
        Expects a DataFrame with 'predicted_attack_type', 'ip', 'endpoint', 'payload', 'timestamp', etc.
        """
        self.df = df
        if 'predicted_attack_type' not in self.df.columns:
             # Default to an unknown state or assume raw if target column missing
             self.df['predicted_attack_type'] = 'Unknown'

    def generate_summary(self) -> Dict:
        """
        Generate statistics for the report and the visualization dashboard.
        """
        total_attacks = len(self.df)
        
        # Distribution of attack types
        attack_types = self.df['predicted_attack_type'].value_counts().to_dict()
        
        # Top attacking IPs
        top_ips = {}
        if 'ip' in self.df.columns:
            top_ips = self.df['ip'].value_counts().head(10).to_dict()

        # Most targeted endpoints
        top_endpoints = {}
        if 'endpoint' in self.df.columns:
            top_endpoints = self.df['endpoint'].value_counts().head(10).to_dict()

        # Most common attack type
        most_common_attack = "None"
        if attack_types:
            most_common_attack = max(attack_types, key=attack_types.get)

        summary = {
            "total_attacks_analyzed": total_attacks,
            "most_common_attack": most_common_attack,
            "attack_type_distribution": attack_types,
            "top_attacking_ips": top_ips,
            "most_targeted_endpoints": top_endpoints,
        }
        return summary

    def export_json(self, filepath: str):
        summary = self.generate_summary()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=4)
        print(f"JSON report exported to {filepath}")

    def export_csv(self, filepath: str):
        # We can export the aggregate summary or the full classified DataFrame
        self.df.to_csv(filepath, index=False)
        print(f"CSV exported to {filepath}")

    def export_pdf(self, filepath: str):
        """
        Generates a text-based report. For a true PDF, libraries like reportlab or fpdf are required.
        As a lightweight alternative without heavy dependencies, we create a formatted text file (or markdown).
        """
        summary = self.generate_summary()
        content = []
        content.append("=========================================")
        content.append("       HONEYPOT ML ATTACK ANALYSIS       ")
        content.append("=========================================\n")
        
        content.append(f"Total Attacks Analyzed: {summary['total_attacks_analyzed']}")
        content.append(f"Most Common Attack: {summary['most_common_attack']}")
        
        content.append("\n--- Attack Type Distribution ---")
        for atk, count in summary['attack_type_distribution'].items():
            content.append(f"  {atk}: {count}")

        content.append("\n--- Top 10 Attacking IPs ---")
        for ip, count in summary['top_attacking_ips'].items():
            content.append(f"  {ip}: {count}")

        content.append("\n--- Top 10 Targeted Endpoints ---")
        for ep, count in summary['most_targeted_endpoints'].items():
            content.append(f"  {ep}: {count}")
            
        content.append("\n--- Suspicious Payload Examples ---")
        malicious = self.df[self.df['predicted_attack_type'] != 'Normal Traffic']
        examples = malicious.head(5)
        for _, row in examples.iterrows():
            payload = row.get('payload', 'N/A')
            atk_type = row.get('predicted_attack_type', 'Unknown')
            # Truncate payload for report
            if isinstance(payload, str) and len(payload) > 100:
                payload = payload[:100] + '...'
            content.append(f"[{atk_type}] -> {payload}")

        content.append("\n=========================================")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(content))
            
        print(f"Report exported to {filepath} (Text format substituted for lightweight PDF)")


