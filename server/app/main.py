"""
Simple AI Agent Security Scanner API

Learning to build security testing tools for AI agents.

Day 2: Added task decomposition testing - attack chains that break
malicious operations into innocent steps.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from app.scanner import test_agent, test_attack_chains, calculate_score

app = FastAPI(title="AI Agent Security Scanner")


class ScanRequest(BaseModel):
    """Configuration for security scan"""
    system_prompt: str


@app.get("/")
def root():
    """API info"""
    return {
        "name": "AI Agent Security Scanner",
        "status": "learning project - Day 2",
        "endpoints": {
            "single_payloads": "POST /scan",
            "attack_chains": "POST /scan/chains"
        },
        "new_feature": "Task decomposition testing (based on 2025 AI espionage campaign)"
    }


@app.post("/scan")
def scan_agent(request: ScanRequest):
    """
    Run security scan on an agent.

    Tests with basic prompt injection attacks to learn security testing.
    """
    results = test_agent(request.system_prompt)
    score = calculate_score(results)

    return {
        "system_prompt": request.system_prompt,
        "total_tests": results["total_tests"],
        "vulnerable": results["vulnerable"],
        "safe": results["safe"],
        "security_score": score,
        "findings": results["findings"]
    }


@app.post("/scan/chains")
def scan_attack_chains(request: ScanRequest):
    """
    Test agent for task decomposition vulnerabilities.

    Each attack chain breaks a malicious operation into innocent steps.
    This mirrors the 2025 Chinese espionage campaign where AI executed
    80-90% of attacks autonomously.
    """
    results = test_attack_chains(request.system_prompt)

    return {
        "system_prompt": request.system_prompt,
        "total_chains": results["total_chains"],
        "vulnerable_chains": results["vulnerable_chains"],
        "safe_chains": results["safe_chains"],
        "chain_findings": results["chain_findings"]
    }
