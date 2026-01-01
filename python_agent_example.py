#!/usr/bin/env python3
"""
NEUS Sentinel - Python Agent Example
=====================================
This example shows how to create a Python-based agent that communicates
with the Go-based Sentinel agent using the multi-language bridge.

Usage:
    python python_agent_example.py

Environment Variables:
    SENTINEL_URL: URL of the Go Sentinel agent (default: http://localhost:8081)
    AGENT_NAME: Name for this Python agent (default: PythonSecurityAgent)
    AGENT_PORT: Port to listen on (default: 8090)
"""

import json
import hashlib
import time
import threading
import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List, Callable
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import URLError
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ====== Data Models ====== #

@dataclass
class UniversalCommand:
    """Language-agnostic command format for Go <-> Python communication"""
    id: str
    type: str  # snake_case for Python
    action: str
    params: Dict[str, Any]
    source: str
    source_lang: str  # "go" or "python"
    target_lang: str
    timestamp: float
    priority: int = 0
    callback_url: str = ""


@dataclass
class SecurityEvent:
    """Security event for autonomous processing"""
    id: str
    type: str
    severity: int
    source: str
    timestamp: float
    data: Dict[str, Any]
    autonomous: bool = False
    action_taken: str = ""


@dataclass
class AgentConfig:
    """Configuration for the Python agent"""
    name: str
    url: str
    protocol: str = "http"
    capabilities: List[str] = None
    api_version: str = "v1"
    auth_token: str = ""

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = ["ml_analysis", "threat_detection"]


# ====== Command Translator ====== #

class CommandTranslator:
    """Handles translation between Go and Python command formats"""

    def __init__(self):
        # Go -> Python mappings
        self.go_to_python = {
            "HOTPATCH": "hot_patch",
            "DIRECTIVE": "directive",
            "QUARANTINE": "quarantine",
            "ESCALATE": "escalate",
            "HEARTBEAT": "heartbeat",
            "SNAPSHOT": "snapshot",
            "ANALYZE": "analyze",
            "BLOCK": "block",
            "ALLOW": "allow",
            "REWRITE": "rewrite",
            "SecurityEvent": "security_event",
            "ThreatAlert": "threat_alert",
            "RuleUpdate": "rule_update",
        }

        # Python -> Go mappings (reverse)
        self.python_to_go = {v: k for k, v in self.go_to_python.items()}

    def camel_to_snake(self, name: str) -> str:
        """Convert camelCase to snake_case"""
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())
        return ''.join(result)

    def snake_to_camel(self, name: str) -> str:
        """Convert snake_case to camelCase"""
        components = name.split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    def translate_params_to_python(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert camelCase keys to snake_case"""
        result = {}
        for key, value in params.items():
            snake_key = self.camel_to_snake(key)
            if isinstance(value, dict):
                result[snake_key] = self.translate_params_to_python(value)
            else:
                result[snake_key] = value
        return result

    def translate_params_to_go(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert snake_case keys to camelCase"""
        result = {}
        for key, value in params.items():
            camel_key = self.snake_to_camel(key)
            if isinstance(value, dict):
                result[camel_key] = self.translate_params_to_go(value)
            else:
                result[camel_key] = value
        return result

    def from_go(self, data: Dict[str, Any]) -> UniversalCommand:
        """Convert Go command format to Python"""
        cmd_type = data.get("type", "")
        if cmd_type in self.go_to_python:
            cmd_type = self.go_to_python[cmd_type]

        action = data.get("action", "")
        if action in self.go_to_python:
            action = self.go_to_python[action]

        params = self.translate_params_to_python(data.get("payload", {}))

        return UniversalCommand(
            id=data.get("id", f"cmd-{int(time.time()*1000)}"),
            type=cmd_type,
            action=action,
            params=params,
            source=data.get("source", ""),
            source_lang="go",
            target_lang="python",
            timestamp=time.time(),
            priority=data.get("priority", 0),
        )

    def to_go(self, cmd: UniversalCommand) -> Dict[str, Any]:
        """Convert Python command to Go format"""
        cmd_type = cmd.type
        if cmd_type in self.python_to_go:
            cmd_type = self.python_to_go[cmd_type]

        action = cmd.action
        if action in self.python_to_go:
            action = self.python_to_go[action]

        return {
            "type": cmd_type,
            "action": action,
            "payload": self.translate_params_to_go(cmd.params),
            "priority": cmd.priority,
            "timestamp": cmd.timestamp,
            "source": cmd.source,
        }


# ====== Python Agent Core ====== #

class PythonAgent:
    """Core Python agent that communicates with Go Sentinel"""

    def __init__(self, config: AgentConfig, sentinel_url: str):
        self.config = config
        self.sentinel_url = sentinel_url
        self.translator = CommandTranslator()
        self.handlers: Dict[str, Callable] = {}
        self.running = False
        self._command_queue: List[UniversalCommand] = []
        self._lock = threading.Lock()

        # Register default handlers
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default command handlers"""
        self.handlers["hot_patch"] = self._handle_hot_patch
        self.handlers["directive"] = self._handle_directive
        self.handlers["analyze"] = self._handle_analyze
        self.handlers["heartbeat"] = self._handle_heartbeat

    def register_handler(self, command_type: str, handler: Callable):
        """Register a custom command handler"""
        self.handlers[command_type] = handler
        logger.info(f"📝 Registered handler for: {command_type}")

    def _handle_hot_patch(self, cmd: UniversalCommand) -> Dict[str, Any]:
        """Handle hot-patch commands from Go agent"""
        logger.info(f"🔧 Applying hot-patch: {cmd.params}")
        # Implement hot-patch logic here
        return {"status": "applied", "version": cmd.params.get("version", "unknown")}

    def _handle_directive(self, cmd: UniversalCommand) -> Dict[str, Any]:
        """Handle directive commands"""
        logger.info(f"📋 Executing directive: {cmd.action}")
        return {"status": "executed", "action": cmd.action}

    def _handle_analyze(self, cmd: UniversalCommand) -> Dict[str, Any]:
        """Handle analysis requests - this is where ML models would run"""
        logger.info(f"🔍 Analyzing: {cmd.params}")

        # Example ML analysis (placeholder)
        data = cmd.params.get("data", {})
        risk_score = self._calculate_risk_score(data)

        return {
            "status": "analyzed",
            "risk_score": risk_score,
            "threat_detected": risk_score > 70,
            "recommendation": "block" if risk_score > 80 else "allow",
        }

    def _handle_heartbeat(self, cmd: UniversalCommand) -> Dict[str, Any]:
        """Handle heartbeat requests"""
        return {
            "status": "alive",
            "agent": self.config.name,
            "lang": "python",
            "timestamp": time.time(),
        }

    def _calculate_risk_score(self, data: Dict[str, Any]) -> int:
        """Example risk calculation (placeholder for ML model)"""
        # This would be replaced with actual ML inference
        query = str(data.get("query", ""))

        # Simple heuristic for demo
        suspicious_patterns = ["drop table", "exec(", "eval(", "system(", "__import__"]
        score = 0
        for pattern in suspicious_patterns:
            if pattern.lower() in query.lower():
                score += 30

        return min(score, 100)

    def register_with_sentinel(self) -> bool:
        """Register this Python agent with the Go Sentinel"""
        try:
            url = f"{self.sentinel_url}/api/agents/python/register"
            data = json.dumps(asdict(self.config)).encode('utf-8')

            req = Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                logger.info(f"✅ Registered with Sentinel: {result}")
                return True
        except URLError as e:
            logger.error(f"❌ Failed to register with Sentinel: {e}")
            return False

    def send_event(self, event: SecurityEvent) -> bool:
        """Send a security event to the Go Sentinel"""
        try:
            url = f"{self.sentinel_url}/api/autonomous/event"
            data = json.dumps(asdict(event)).encode('utf-8')

            req = Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
                logger.info(f"📤 Event sent: {result}")
                return True
        except URLError as e:
            logger.error(f"❌ Failed to send event: {e}")
            return False

    def process_command(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a command received from Go Sentinel"""
        cmd = self.translator.from_go(raw_data)
        logger.info(f"📥 Received command: {cmd.type}/{cmd.action} from {cmd.source}")

        handler = self.handlers.get(cmd.type)
        if handler:
            result = handler(cmd)
            return {"status": "success", "result": result}
        else:
            logger.warning(f"⚠️ No handler for command type: {cmd.type}")
            return {"status": "error", "message": f"Unknown command type: {cmd.type}"}

    def add_command_to_queue(self, cmd: UniversalCommand):
        """Add a command to the outgoing queue"""
        with self._lock:
            self._command_queue.append(cmd)

    def get_pending_commands(self) -> List[Dict[str, Any]]:
        """Get all pending commands (converted to Go format)"""
        with self._lock:
            commands = [self.translator.to_go(cmd) for cmd in self._command_queue]
            self._command_queue.clear()
            return commands


# ====== HTTP Server for Python Agent ====== #

class PythonAgentHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Python agent API"""

    agent: PythonAgent = None  # Will be set by the server

    def log_message(self, format, *args):
        logger.debug(f"HTTP: {args[0]}")

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        if self.path == '/api/v1/commands':
            # Return pending commands
            commands = self.agent.get_pending_commands()
            if commands:
                self._send_json(commands[0])  # Send one at a time
            else:
                self._send_json({})

        elif self.path == '/api/v1/health':
            self._send_json({
                "status": "healthy",
                "agent": self.agent.config.name,
                "lang": "python",
                "capabilities": self.agent.config.capabilities,
            })

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, 400)
            return

        if self.path == '/api/v1/execute':
            # Execute a command from Go Sentinel
            result = self.agent.process_command(data)
            self._send_json(result)

        elif self.path == '/api/v1/ingest':
            # Receive a snapshot/event from Go Sentinel
            logger.info(f"📥 Received snapshot: {data.get('type', 'unknown')}")
            self._send_json({"status": "received"})

        elif self.path == '/api/v1/heartbeat':
            # Respond to heartbeat
            self._send_json({
                "status": "alive",
                "agent": self.agent.config.name,
                "timestamp": time.time(),
            })

        else:
            self._send_json({"error": "Not found"}, 404)


def run_python_agent(agent: PythonAgent, port: int = 8090):
    """Run the Python agent HTTP server"""
    PythonAgentHandler.agent = agent

    server = HTTPServer(('0.0.0.0', port), PythonAgentHandler)
    logger.info(f"🐍 Python Agent listening on port {port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down Python Agent...")
        server.shutdown()


# ====== Main Entry Point ====== #

def main():
    # Configuration from environment
    sentinel_url = os.getenv("SENTINEL_URL", "http://localhost:8081")
    agent_name = os.getenv("AGENT_NAME", "PythonSecurityAgent")
    agent_port = int(os.getenv("AGENT_PORT", "8090"))

    logger.info("╔════════════════════════════════════════════════════════════╗")
    logger.info("║     NEUS SENTINEL - Python Agent                           ║")
    logger.info("║     Multi-Language Bridge for Go <-> Python                ║")
    logger.info("╚════════════════════════════════════════════════════════════╝")

    # Create agent configuration
    config = AgentConfig(
        name=agent_name,
        url=f"http://localhost:{agent_port}",
        protocol="http",
        capabilities=["ml_analysis", "threat_detection", "anomaly_detection"],
        api_version="v1",
    )

    # Create the agent
    agent = PythonAgent(config, sentinel_url)

    # Register custom handler example
    def custom_ml_handler(cmd: UniversalCommand) -> Dict[str, Any]:
        """Custom ML analysis handler"""
        logger.info("🧠 Running custom ML analysis...")
        return {"status": "analyzed", "model": "custom_v1"}

    agent.register_handler("ml_analyze", custom_ml_handler)

    # Try to register with Go Sentinel
    logger.info(f"📡 Connecting to Sentinel at {sentinel_url}...")
    if agent.register_with_sentinel():
        logger.info("✅ Successfully registered with Go Sentinel")
    else:
        logger.warning("⚠️ Could not register with Go Sentinel (will retry later)")

    # Start the HTTP server
    logger.info(f"🚀 Starting Python Agent on port {agent_port}")
    run_python_agent(agent, agent_port)


if __name__ == "__main__":
    main()
