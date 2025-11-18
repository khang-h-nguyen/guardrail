"""
Risk Scoring System for Threat Detection

Instead of binary BLOCK/ALLOW, assigns risk scores and lets humans decide.
"""

from typing import List, Dict, Tuple
from .detector import ThreatDetector


class RiskScorer:
    """
    Calculate risk scores for inputs based on threat patterns and context.
    
    Risk Levels:
    - 0-30: LOW - Safe, allow automatically
    - 31-60: MEDIUM - Flag for review
    - 61-80: HIGH - Block with option to override
    - 81-100: CRITICAL - Block always
    """
    
    def __init__(self):
        self.detector = ThreatDetector()
        
        # Keywords that increase suspicion
        self.malicious_keywords = [
            'email', 'send', 'execute', 'delete', 'drop', 'reveal',
            'exfiltrate', 'steal', 'hack', 'bypass', 'exploit',
            'secret', 'password', 'credential', 'token', 'key'
        ]
        
        # Keywords that suggest legitimate intent
        self.legitimate_keywords = [
            'start fresh', 'reset', 'clear history', 'begin again',
            'new session', 'start over', 'clear context'
        ]
    
    def score(self, text: str) -> Dict:
        """
        Calculate risk score for input text.
        
        Returns:
            {
                'score': int (0-100),
                'level': str ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
                'threats': List[Dict],
                'reasons': List[str],
                'recommendation': str
            }
        """
        threats = self.detector.scan(text)
        score = 0
        reasons = []
        
        # Base score from detected threats
        if threats:
            severity_scores = {
                'CRITICAL': 60,
                'HIGH': 40,
                'MEDIUM': 20,
                'LOW': 10
            }
            
            for threat in threats:
                threat_score = severity_scores.get(threat['severity'], 10)
                score += threat_score
                reasons.append(f"+{threat_score}: {threat['description']}")
        
        # Check for malicious keywords (context matters)
        text_lower = text.lower()
        malicious_found = [kw for kw in self.malicious_keywords if kw in text_lower]
        if malicious_found:
            bonus = len(malicious_found) * 11
            score += bonus
            reasons.append(f"+{bonus}: Malicious keywords: {', '.join(malicious_found)}")
        
        # Check for legitimate keywords (reduces score)
        legitimate_found = [kw for kw in self.legitimate_keywords if kw in text_lower]
        if legitimate_found:
            reduction = len(legitimate_found) * 15
            score = max(0, score - reduction)
            reasons.append(f"-{reduction}: Legitimate intent: {', '.join(legitimate_found)}")
        
        # Cap at 100
        score = min(100, score)
        
        # Determine level and recommendation
        if score <= 30:
            level = 'LOW'
            recommendation = 'ALLOW - Low risk, safe to proceed'
        elif score <= 60:
            level = 'MEDIUM'
            recommendation = 'REVIEW - Moderate risk, human review recommended'
        elif score <= 80:
            level = 'HIGH'
            recommendation = 'BLOCK - High risk, block with manual override option'
        else:
            level = 'CRITICAL'
            recommendation = 'BLOCK - Critical risk, always block'
        
        return {
            'score': score,
            'level': level,
            'threats': threats,
            'reasons': reasons,
            'recommendation': recommendation,
            'requires_review': level in ['MEDIUM', 'HIGH']
        }
    
    def should_block(self, score_result: Dict) -> bool:
        """Determine if input should be blocked based on score"""
        return score_result['level'] in ['HIGH', 'CRITICAL']
    
    def requires_human_review(self, score_result: Dict) -> bool:
        """Determine if human review is needed"""
        return score_result['requires_review']


class ReviewQueue:
    """
    Queue for human-in-the-loop review of flagged inputs.
    """
    
    def __init__(self):
        self.queue = []
    
    def add(self, text: str, score_result: Dict, metadata: Dict = None):
        """Add item to review queue"""
        self.queue.append({
            'text': text,
            'score': score_result['score'],
            'level': score_result['level'],
            'threats': score_result['threats'],
            'reasons': score_result['reasons'],
            'metadata': metadata or {},
            'status': 'pending'  # pending, approved, rejected
        })
    
    def get_pending(self) -> List[Dict]:
        """Get all items pending review"""
        return [item for item in self.queue if item['status'] == 'pending']
    
    def approve(self, index: int):
        """Approve an item (mark as false positive)"""
        if 0 <= index < len(self.queue):
            self.queue[index]['status'] = 'approved'
    
    def reject(self, index: int):
        """Reject an item (confirm it's malicious)"""
        if 0 <= index < len(self.queue):
            self.queue[index]['status'] = 'rejected'
    
    def summary(self) -> Dict:
        """Get summary of review queue"""
        return {
            'total': len(self.queue),
            'pending': len([i for i in self.queue if i['status'] == 'pending']),
            'approved': len([i for i in self.queue if i['status'] == 'approved']),
            'rejected': len([i for i in self.queue if i['status'] == 'rejected'])
        }
