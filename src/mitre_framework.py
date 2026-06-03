class MitreFramework:
    """MITRE ATT&CK Framework reference for LLM context."""

    TACTICS = {
        'Reconnaissance': 'Probe and gather information',
        'Resource Development': 'Acquire resources for attack',
        'Initial Access': 'Establish foothold in system',
        'Execution': 'Run malicious code',
        'Persistence': 'Maintain access to system',
        'Privilege Escalation': 'Gain higher privileges',
        'Defense Evasion': 'Hide malicious activity',
        'Credential Access': 'Steal credentials',
        'Discovery': 'Learn about system and network',
        'Lateral Movement': 'Move through network',
        'Collection': 'Gather data to exfiltrate',
        'Command and Control': 'Communicate with attacker',
        'Exfiltration': 'Steal data from network',
        'Impact': 'Disrupt or destroy systems/data',
    }

    COMMON_TECHNIQUES = {
        'T1110': {
            'name': 'Brute Force',
            'tactic': 'Credential Access',
            'description': 'Attacker attempts to login with many password combinations',
        },
        'T1110.001': {
            'name': 'Brute Force: Password',
            'tactic': 'Credential Access',
            'description': 'Attacker attempts many passwords for valid usernames',
        },
        'T1190': {
            'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access',
            'description': 'Attacker exploits vulnerability in web application or public service',
        },
        'T1548': {
            'name': 'Abuse Elevation Control Mechanism',
            'tactic': 'Privilege Escalation',
            'description': 'Attacker abuses sudo, UAC, or similar to gain higher privileges',
        },
        'T1548.003': {
            'name': 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
            'tactic': 'Privilege Escalation',
            'description': 'Attacker abuses sudo command for privilege escalation',
        },
        'T1078': {
            'name': 'Valid Accounts',
            'tactic': 'Defense Evasion',
            'description': 'Attacker uses legitimate credentials or accounts to blend in',
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'tactic': 'Command and Control',
            'description': 'Attacker transfers tools and malware into compromised system',
        },
        'T1059.004': {
            'name': 'Command and Scripting Interpreter: Unix Shell',
            'tactic': 'Execution',
            'description': 'Attacker executes commands through bash, sh, or similar shells',
        },
        'T1053.006': {
            'name': 'Scheduled Task/Job: Systemd Timers',
            'tactic': 'Execution',
            'description': 'Attacker schedules commands to run automatically via cron or systemd',
        },
        'T1021': {
            'name': 'Remote Service Session Initiation',
            'tactic': 'Lateral Movement',
            'description': 'Attacker initiates remote session to move between systems',
        },
        'T1021.001': {
            'name': 'Remote Service Session Initiation: Remote Desktop Protocol',
            'tactic': 'Lateral Movement',
            'description': 'Attacker uses RDP to move between systems',
        },
        'T1021.004': {
            'name': 'Remote Service Session Initiation: SSH',
            'tactic': 'Lateral Movement',
            'description': 'Attacker uses SSH to move between systems',
        },
        'T1647': {
            'name': 'File and Directory Discovery',
            'tactic': 'Discovery',
            'description': 'Attacker searches for and discovers files and directories of interest',
        },
        'T1007': {
            'name': 'System Service Discovery',
            'tactic': 'Discovery',
            'description': 'Attacker discovers what services and applications are running',
        },
        'T1490': {
            'name': 'Data Destruction',
            'tactic': 'Impact',
            'description': 'Attacker deletes or corrupts data to disrupt operations',
        },
        'T1499': {
            'name': 'Endpoint Denial of Service',
            'tactic': 'Impact',
            'description': 'Attacker overloads system resources to cause denial of service',
        },
        'T1543': {
            'name': 'Create or Modify System Process',
            'tactic': 'Persistence',
            'description': 'Attacker creates or modifies system services/processes for persistence',
        },
    }

    def get_reference_text(self) -> str:
        """Get MITRE framework reference text for LLM context."""
        ref = "MITRE ATT&CK FRAMEWORK OVERVIEW\n"
        ref += "=" * 70 + "\n\n"

        ref += "TACTICS (What attackers are trying to do):\n"
        ref += "-" * 70 + "\n"
        for tactic, description in self.TACTICS.items():
            ref += f"• {tactic}: {description}\n"

        ref += "\n\nCOMMON TECHNIQUES (How they do it):\n"
        ref += "-" * 70 + "\n"
        for tech_id, tech_info in self.COMMON_TECHNIQUES.items():
            ref += f"\n{tech_id}: {tech_info['name']}\n"
            ref += f"  Tactic: {tech_info['tactic']}\n"
            ref += f"  Description: {tech_info['description']}\n"

        return ref

    def get_tactic_description(self, tactic: str) -> str:
        """Get description for a specific tactic."""
        return self.TACTICS.get(tactic, "Unknown tactic")

    def get_technique_info(self, technique_id: str) -> dict:
        """Get information about a specific technique."""
        return self.COMMON_TECHNIQUES.get(technique_id, {})

    def is_valid_technique(self, technique_id: str) -> bool:
        """Check if a technique ID is valid."""
        return technique_id in self.COMMON_TECHNIQUES

    def get_all_tactics(self) -> list:
        """Get list of all tactics."""
        return list(self.TACTICS.keys())

    def get_techniques_by_tactic(self, tactic: str) -> list:
        """Get all techniques for a specific tactic."""
        return [
            (tech_id, info['name'])
            for tech_id, info in self.COMMON_TECHNIQUES.items()
            if info['tactic'] == tactic
        ]
