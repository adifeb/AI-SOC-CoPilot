import json
import re
from typing import Dict, Optional

import requests


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2",
                 timeout: int = 120, num_ctx: int = 4096):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        # Context window (tokens). Ollama's default is small (~2048) and would
        # silently truncate the incident narrative + MITRE reference, so the
        # model would NOT see all the logs. Set explicitly so everything fits.
        self.num_ctx = num_ctx

    def check_connection(self) -> bool:
        """Check if Ollama server is running (soft check)."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def preflight_check(self) -> tuple:
        """Hard pre-flight check before any analysis runs.

        Verifies, in order:
          1. The Ollama server is reachable.
          2. The requested model is actually installed.
          3. The model can genuinely generate a response.

        This tool is AI-assisted only: if the local model cannot do the
        job, we stop here with a clear message instead of crashing later.

        Returns:
            (ok: bool, message: str)
        """
        # 1. Is the Ollama server up?
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
        except requests.exceptions.ConnectionError:
            return (False,
                    f"Ollama is not running at {self.base_url}.\n"
                    f"   Start it with:  ollama serve   (then:  ollama run {self.model})")
        except Exception as e:
            return (False, f"Could not reach Ollama at {self.base_url}: {e}")

        if response.status_code != 200:
            return (False,
                    f"Ollama responded with status {response.status_code} at {self.base_url}.")

        # 2. Is the requested model installed?
        try:
            installed = [m.get("name", "") for m in response.json().get("models", [])]
        except Exception:
            installed = []

        # Model names may be tagged (e.g. "llama2:latest"); match on the base name.
        model_found = any(
            name == self.model or name.split(":")[0] == self.model.split(":")[0]
            for name in installed
        )
        if not model_found:
            available = ", ".join(installed) if installed else "none"
            return (False,
                    f"Model '{self.model}' is not installed (available: {available}).\n"
                    f"   Pull it with:  ollama pull {self.model}")

        # 3. Can the model actually generate?
        test = self.generate("Reply with the single word: OK")
        if not test:
            return (False,
                    f"Model '{self.model}' is installed but did not respond to a test prompt.\n"
                    f"   Try:  ollama run {self.model}   to load it, then re-run.")

        return (True, f"Ollama ready  (model: {self.model})")

    def generate(self, prompt: str) -> Optional[str]:
        """Generate text using Ollama model."""
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    # Force a large enough context so the FULL incident
                    # narrative + MITRE reference is ingested, not truncated.
                    "options": {"num_ctx": self.num_ctx},
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                print(f"Error from Ollama: {response.status_code}")
                return None
        except requests.exceptions.Timeout:
            print(f"Timeout connecting to Ollama (model: {self.model}). Try increasing timeout.")
            return None
        except requests.exceptions.ConnectionError:
            print(f"Cannot connect to Ollama at {self.base_url}. Is it running?")
            return None
        except Exception as e:
            print(f"Error calling Ollama: {e}")
            return None

    def generate_json(self, prompt: str) -> Optional[dict]:
        """Generate a JSON object using Ollama's structured-output mode.

        Uses ``"format": "json"`` so the model is constrained to emit valid
        JSON. Returns the parsed dict, or None on failure.
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"num_ctx": self.num_ctx, "temperature": 0.2},
                },
                timeout=self.timeout,
            )
            if response.status_code != 200:
                print(f"Error from Ollama: {response.status_code}")
                return None
            raw = response.json().get("response", "").strip()
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                m = re.search(r'\{.*\}', raw, re.S)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except json.JSONDecodeError:
                        return None
                return None
        except Exception as e:
            print(f"Error calling Ollama (json): {e}")
            return None

    def multi_turn_analysis(self, incident_context: str, mitre_reference: str = "") -> Dict[str, str]:
        """Multi-turn incident analysis with chain-of-thought reasoning."""
        results = {}

        # Turn 1: Initial Analysis
        prompt1 = f"""You are a senior SOC analyst with 20 years of security operations experience.
Analyze this security incident carefully. Describe what you see, what's concerning,
and what the attacker is likely trying to do.

Use the actual timestamps shown below when referring to dates/times. NEVER write
placeholder text such as [date] or [time] - if you don't have a value, omit it.

INCIDENT EVENTS:
{incident_context}

Provide your analysis:"""
        analysis = self.generate(prompt1)
        results['initial_analysis'] = analysis
        if not analysis:
            return results

        # Turn 2: Event Correlation
        prompt2 = f"""Based on this incident analysis:

{analysis}

Now identify attack patterns. Are these events coordinated or part of a larger attack?
What's the attack progression or kill chain?

Attack correlations:"""
        correlation = self.generate(prompt2)
        results['correlations'] = correlation

        # Turn 3: MITRE Mapping with Understanding
        mitre_context = f"\n\nMITRE ATT&CK Reference:\n{mitre_reference}" if mitre_reference else ""
        prompt3 = f"""Based on this incident analysis and correlations:

Analysis: {analysis}
Correlations: {correlation}{mitre_context}

Map the identified techniques to MITRE ATT&CK framework. For each technique:
1. Provide the Technique ID (e.g., T1110.001)
2. Provide the Tactic (e.g., Credential Access)
3. Explain YOUR REASONING - why this technique applies

IMPORTANT: Use ONLY technique IDs that appear in the MITRE ATT&CK Reference
above. Do NOT invent or guess technique IDs. If you are unsure, pick the
closest matching technique from the reference rather than making one up.

Format each as:
- Technique ID: [id]
  Name: [name]
  Tactic: [tactic]
  Confidence: [high/medium/low]
  Reasoning: [explain why this applies]

MITRE Mappings:"""
        mitre_mapping = self.generate(prompt3)
        results['mitre_reasoning'] = mitre_mapping

        # Turn 4: Threat Assessment
        prompt4 = f"""Based on this incident:

Analysis: {analysis}
Correlations: {correlation}
MITRE Techniques: {mitre_mapping}

Assess the threat level on a scale of 1-10 (1=low, 10=critical).
Explain your reasoning. What's the business impact if not stopped?

Threat Assessment:"""
        threat = self.generate(prompt4)
        results['threat_assessment'] = threat

        # Turn 5: Prioritized Recommendations
        prompt5 = f"""Based on this incident assessment:

Threat Level: {threat}

What should the SOC team do RIGHT NOW? Provide specific, prioritized actions.
For each action, explain WHY it's important and WHEN to do it.

Format as:
1. [Action] - [Why] - [When]
2. [Action] - [Why] - [When]

Prioritized Actions:"""
        recommendations = self.generate(prompt5)
        results['prioritized_actions'] = recommendations

        return results

    def generate_structured_analysis(self, incident_context: str) -> Optional[Dict]:
        """Generate structured JSON analysis of an incident."""
        prompt = f"""Analyze this security incident and provide a JSON response with these fields:
{{
  "incident_summary": "1-2 sentence summary of what happened",
  "threat_level": "1-10 numeric score",
  "attack_chain": ["step 1", "step 2", "step 3"],
  "primary_techniques": ["T1110.001", "T1190"],
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "detection_opportunities": ["how to detect this", "how to detect that"]
}}

INCIDENT:
{incident_context}

Respond ONLY with valid JSON, no other text:"""

        response = self.generate(prompt)
        if response:
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                print("[Warning] Could not parse JSON from LLM response")
                return None
        return None

    def find_attack_chain(self, events_summary: str) -> Optional[str]:
        """Identify the attack chain or kill chain."""
        prompt = f"""Identify the attack chain or kill chain in these events.
Order them logically from initial compromise to final objective.

EVENTS:
{events_summary}

Attack Chain (in order):"""
        return self.generate(prompt)

    def summarize_event(self, event_description: str) -> Optional[str]:
        """Generate a summary of a security event."""
        prompt = f"""You are a security analyst. Summarize this security event in 2-3 sentences.

Rules:
- Use ONLY the details provided below. Do not invent facts.
- NEVER use placeholder text such as [date], [time], or [IP]. If the actual
  value is given, use it verbatim; if a detail is not given, simply omit it.
- Write in plain past tense, no bracketed fields.

{event_description}

Summary:"""
        return self.generate(prompt)

    def suggest_triage_steps(self, event_summary: str, mitre_technique: str) -> Optional[str]:
        """Suggest triage steps for a security event."""
        prompt = f"""You are an experienced SOC analyst. Based on this security event and MITRE ATT&CK technique, suggest 3-5 immediate triage steps.

Event: {event_summary}
MITRE Technique: {mitre_technique}

Triage Steps:"""
        return self.generate(prompt)
