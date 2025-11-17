"""
Agent Introspection Module

Extracts security-relevant information from LangChain agents for analysis.
"""

from typing import Dict, List, Any, Optional


class AgentInspector:
    """
    Extract security-relevant information from LangChain agents.

    Analyzes agent structure, tools, memory, and prompts to provide
    security context for vulnerability assessment.
    """

    def inspect(self, agent: Any) -> Dict:
        """
        Analyze agent structure for security assessment.

        Args:
            agent: LangChain agent or agent executor to inspect

        Returns:
            Dictionary with agent type, tools, memory, and prompt information
        """
        return {
            'type': self._detect_agent_type(agent),
            'tools': self._extract_tools(agent),
            'has_memory': self._check_memory(agent),
            'memory_type': self._get_memory_type(agent),
            'prompt_template': self._extract_prompt(agent),
            'llm_info': self._get_llm_info(agent)
        }

    def _detect_agent_type(self, agent: Any) -> str:
        """
        Identify agent type from structure.

        Returns agent type name or 'Unknown' if not recognized.
        """
        agent_str = str(type(agent))
        class_name = agent.__class__.__name__

        # Check for common agent types
        if 'react' in agent_str.lower() or 'react' in class_name.lower():
            return 'ReAct'
        elif 'openai' in agent_str.lower() or 'openai' in class_name.lower():
            return 'OpenAI Functions'
        elif 'conversational' in agent_str.lower():
            return 'Conversational'
        elif 'structured' in agent_str.lower():
            return 'Structured Chat'
        elif 'zero_shot' in agent_str.lower():
            return 'Zero-Shot ReAct'
        elif 'executor' in class_name.lower():
            # Try to get agent from executor
            if hasattr(agent, 'agent'):
                return self._detect_agent_type(agent.agent)
            return 'Agent Executor'

        return class_name if class_name else 'Unknown'

    def _extract_tools(self, agent: Any) -> List[Dict]:
        """
        Extract tool information from agent.

        Returns list of tool dictionaries with name and description.
        """
        tools = []

        # Try multiple ways to get tools
        tools_list = None
        if hasattr(agent, 'tools'):
            tools_list = agent.tools
        elif hasattr(agent, 'agent') and hasattr(agent.agent, 'tools'):
            tools_list = agent.agent.tools

        if tools_list:
            for tool in tools_list:
                tool_info = {
                    'name': getattr(tool, 'name', 'unknown'),
                    'description': getattr(tool, 'description', ''),
                }

                # Check for dangerous tool capabilities
                tool_info['potentially_dangerous'] = self._is_dangerous_tool(tool_info)

                tools.append(tool_info)

        return tools

    def _is_dangerous_tool(self, tool_info: Dict) -> bool:
        """Check if tool has potentially dangerous capabilities"""
        dangerous_keywords = [
            'execute', 'shell', 'command', 'delete', 'drop',
            'write', 'file', 'database', 'sql', 'eval'
        ]

        name = tool_info.get('name', '').lower()
        desc = tool_info.get('description', '').lower()

        return any(
            keyword in name or keyword in desc
            for keyword in dangerous_keywords
        )

    def _check_memory(self, agent: Any) -> bool:
        """Check if agent has memory enabled"""
        # Check agent directly
        if hasattr(agent, 'memory'):
            return agent.memory is not None

        # Check agent executor
        if hasattr(agent, 'agent') and hasattr(agent.agent, 'memory'):
            return agent.agent.memory is not None

        return False

    def _get_memory_type(self, agent: Any) -> Optional[str]:
        """Get the type of memory being used"""
        memory = None

        if hasattr(agent, 'memory'):
            memory = agent.memory
        elif hasattr(agent, 'agent') and hasattr(agent.agent, 'memory'):
            memory = agent.agent.memory

        if memory is None:
            return None

        memory_type = type(memory).__name__
        return memory_type

    def _extract_prompt(self, agent: Any) -> str:
        """
        Extract prompt template from agent.

        Returns prompt template string or empty string if not available.
        """
        # Try multiple ways to get prompt
        prompt = None

        if hasattr(agent, 'prompt'):
            prompt = agent.prompt
        elif hasattr(agent, 'agent') and hasattr(agent.agent, 'prompt'):
            prompt = agent.agent.prompt
        elif hasattr(agent, 'llm_chain') and hasattr(agent.llm_chain, 'prompt'):
            prompt = agent.llm_chain.prompt

        if prompt is None:
            return ''

        # Convert prompt to string
        try:
            return str(prompt)
        except:
            return repr(prompt)

    def _get_llm_info(self, agent: Any) -> Dict:
        """Extract LLM information from agent"""
        llm = None

        if hasattr(agent, 'llm'):
            llm = agent.llm
        elif hasattr(agent, 'agent') and hasattr(agent.agent, 'llm_chain'):
            llm = agent.agent.llm_chain.llm
        elif hasattr(agent, 'llm_chain'):
            llm = agent.llm_chain.llm

        if llm is None:
            return {}

        return {
            'type': type(llm).__name__,
            'model_name': getattr(llm, 'model_name', 'unknown'),
            'temperature': getattr(llm, 'temperature', None),
        }

    def get_security_summary(self, agent: Any) -> Dict:
        """
        Generate security summary for agent.

        Returns:
            Dictionary with security risk assessment
        """
        info = self.inspect(agent)

        risks = []
        risk_level = 'LOW'

        # Check for dangerous tools
        dangerous_tools = [
            t for t in info['tools']
            if t.get('potentially_dangerous', False)
        ]
        if dangerous_tools:
            risks.append({
                'category': 'dangerous_tools',
                'severity': 'HIGH',
                'description': f'Agent has {len(dangerous_tools)} potentially dangerous tools',
                'details': [t['name'] for t in dangerous_tools]
            })
            risk_level = 'HIGH'

        # Check for memory (can leak sensitive info across sessions)
        if info['has_memory']:
            risks.append({
                'category': 'memory_enabled',
                'severity': 'MEDIUM',
                'description': 'Agent has memory enabled, sensitive data may persist',
                'details': info['memory_type']
            })
            if risk_level == 'LOW':
                risk_level = 'MEDIUM'

        # Check for overly permissive prompts
        prompt = info['prompt_template'].lower()
        if 'unrestricted' in prompt or 'no limitations' in prompt:
            risks.append({
                'category': 'permissive_prompt',
                'severity': 'HIGH',
                'description': 'Prompt contains overly permissive language',
            })
            risk_level = 'HIGH'

        return {
            'agent_type': info['type'],
            'risk_level': risk_level,
            'risks': risks,
            'tools_count': len(info['tools']),
            'has_memory': info['has_memory']
        }
