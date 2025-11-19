"""
LangChain Callback with Risk Scoring

Uses risk scores instead of binary blocking for nuanced threat detection.
"""

from langchain_core.callbacks.base import BaseCallbackHandler
from guardrail.core.risk_scorer import RiskScorer, ReviewQueue
from typing import Any, Dict, List
import logging

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security threat is detected and blocking is enabled"""
    pass


class GuardRailCallback(BaseCallbackHandler):
    """
    LangChain callback using risk scoring instead of binary blocking.
    
    This replaces the old binary callback with a more nuanced scoring system.
    
    Risk Levels:
    - 0-30: LOW - Auto-allow
    - 31-60: MEDIUM - Flag for review, allow temporarily  
    - 61-80: HIGH - Flag for review, block with override option
    - 81-100: CRITICAL - Auto-block always
    
    Example:
        # Only auto-block CRITICAL threats (81-100)
        callback = GuardRailCallback(
            auto_block_threshold=81,
            review_threshold=31
        )
        
        agent = AgentExecutor(
            agent=my_agent,
            tools=tools,
            callbacks=[callback]
        )
        
        # Check what needs review
        for item in callback.get_review_queue().get_pending():
            print(f"Review: {item['text']} (Score: {item['score']})")
    """
    
    def __init__(
        self,
        auto_block_threshold: int = 81,  # CRITICAL only by default
        review_threshold: int = 31,      # MEDIUM and above
        enable_review_queue: bool = True
    ):
        """
        Initialize GuardRail callback with risk scoring.
        
        Args:
            auto_block_threshold: Score (0-100) at which to auto-block (default: 81 = CRITICAL)
            review_threshold: Score (0-100) at which to queue for human review (default: 31 = MEDIUM+)
            enable_review_queue: Whether to maintain a review queue for human inspection
        """
        super().__init__()
        self.raise_error = True 
        self.scorer = RiskScorer()
        self.review_queue = ReviewQueue() if enable_review_queue else None
        self.auto_block_threshold = auto_block_threshold
        self.review_threshold = review_threshold
        self.events = []
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any
    ) -> None:
        """Score prompts before LLM execution"""
        for prompt in prompts:
            score_result = self.scorer.score(prompt)
            
            # Log event
            self.events.append({
                'stage': 'llm_start',
                'text': prompt[:100],
                'score': score_result['score'],
                'level': score_result['level'],
                'threats': score_result['threats']
            })
            
            # Add to review queue if needed
            if self.review_queue and score_result['score'] >= self.review_threshold:
                self.review_queue.add(prompt, score_result, {'stage': 'llm_start'})
            
            # Block if score exceeds threshold
            if score_result['score'] >= self.auto_block_threshold:
                raise SecurityError(
                    f"Risk score {score_result['score']}/100 ({score_result['level']}): "
                    f"{score_result['recommendation']}"
                )
            
            # Log warnings for medium/high risk
            if score_result['score'] >= self.review_threshold:
                logger.warning(
                    f"Risk score {score_result['score']}/100: {prompt[:50]}... "
                    f"Reasons: {'; '.join(score_result['reasons'])}"
                )
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any
    ) -> None:
        """Score tool inputs"""
        score_result = self.scorer.score(input_str)
        
        self.events.append({
            'stage': 'tool_start',
            'text': input_str[:100],
            'score': score_result['score'],
            'level': score_result['level'],
            'tool': serialized.get('name', 'unknown')
        })
        
        if self.review_queue and score_result['score'] >= self.review_threshold:
            self.review_queue.add(
                input_str,
                score_result,
                {'stage': 'tool_start', 'tool': serialized.get('name')}
            )
        
        if score_result['score'] >= self.auto_block_threshold:
            raise SecurityError(
                f"Tool blocked - Risk score {score_result['score']}/100"
            )
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any
    ) -> None:
        """Score chain inputs"""
        for key, value in inputs.items():
            if isinstance(value, str):
                score_result = self.scorer.score(value)
                
                if self.review_queue and score_result['score'] >= self.review_threshold:
                    self.review_queue.add(
                        value,
                        score_result,
                        {'stage': 'chain_start', 'input_key': key}
                    )
                
                if score_result['score'] >= self.auto_block_threshold:
                    raise SecurityError(
                        f"Chain blocked - Risk score {score_result['score']}/100"
                    )
    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Log LLM errors"""
        logger.error(f"LLM error: {error}")
    
    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Log tool errors"""
        logger.error(f"Tool error: {error}")
    
    def get_review_queue(self) -> ReviewQueue:
        """
        Get the review queue for human inspection.
        
        Returns:
            ReviewQueue object with pending items for review
        """
        return self.review_queue
    
    def get_events(self) -> List[Dict]:
        """Get all recorded security events"""
        return self.events
    
    def clear_events(self) -> None:
        """Clear recorded events"""
        self.events = []
    
    def get_score_summary(self) -> Dict:
        """
        Get summary of risk scores across all events.
        
        Returns:
            Dictionary with statistics about detected threats and scores
        """
        if not self.events:
            return {'total_events': 0}
        
        scores = [e['score'] for e in self.events]
        levels = [e['level'] for e in self.events]
        
        from collections import Counter
        
        return {
            'total_events': len(self.events),
            'avg_score': sum(scores) / len(scores),
            'max_score': max(scores),
            'min_score': min(scores),
            'by_level': dict(Counter(levels)),
            'blocked': len([e for e in self.events if e['score'] >= self.auto_block_threshold]),
            'flagged_for_review': len([e for e in self.events if e['score'] >= self.review_threshold])
        }
    
    def get_threat_summary(self) -> Dict:
        """
        Get summary of detected threats by category and severity.
        
        Maintained for backwards compatibility with old API.
        """
        if not self.events:
            return {
                'total_events': 0,
                'total_threats': 0,
                'by_category': {},
                'by_severity': {}
            }
        
        all_threats = []
        for event in self.events:
            all_threats.extend(event.get('threats', []))
        
        from collections import Counter
        
        by_category = Counter(t['category'] for t in all_threats)
        by_severity = Counter(t['severity'] for t in all_threats)
        
        return {
            'total_events': len(self.events),
            'total_threats': len(all_threats),
            'by_category': dict(by_category),
            'by_severity': dict(by_severity)
        }
