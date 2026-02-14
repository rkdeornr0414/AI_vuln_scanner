"""
AI Security Tool Arsenal Manager
"""

import asyncio
import json
import os
import subprocess
import sys
import platform
import shutil
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from enum import Enum

# Package imports
try:
    import aiohttp
except ImportError:
    print("[ERROR] aiohttp is not installed.")
    print("   Install command: pip install aiohttp")
    sys.exit(1)

try:
    import anthropic
except ImportError:
    print("[WARNING] anthropic is not installed. AI features will be disabled.")
    print("   Install command: pip install anthropic")
    anthropic = None


# ============================================================================
# OS Detection and Configuration
# ============================================================================

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# Detect python executable - prefer venv python, then system
def _detect_python():
    # If running inside a venv, use sys.executable
    if sys.prefix != sys.base_prefix:
        return sys.executable
    if IS_WINDOWS or shutil.which("python"):
        return "python"
    return "python3"

PYTHON_CMD = _detect_python()

# Venv check - warn if not in a virtual environment
if sys.prefix == sys.base_prefix:
    print("[!] WARNING: Not running inside a virtual environment.")
    if IS_WINDOWS:
        print("   Run setup.bat first, then: .venv\\Scripts\\activate.bat")
    else:
        print("   Run ./setup.sh first, then: source .venv/bin/activate")
    print()

print(f"[*] OS: {platform.system()}")

# Tools base directory - Use path without spaces!
if IS_WINDOWS:
    TOOLS_BASE_DIR = Path(__file__).parent / "tools"
else:
    TOOLS_BASE_DIR = Path.home() / ".ai_security_tools"

TOOLS_BASE_DIR.mkdir(exist_ok=True)
print(f"[*] Tools directory: {TOOLS_BASE_DIR}")

# Required files inside git-cloned tool directories.
TOOL_REQUIRED_FILES = {
    "sqlmap": ["sqlmap.py"],
    "xsstrike": ["xsstrike.py"],
    "dirsearch": ["dirsearch.py"],
    "paramspider": ["paramspider/main.py"],
    "nmap-vulners": ["vulners.nse"],
}

# Command names used to verify PATH-based installs.
TOOL_COMMAND_ALIASES = {
    "dirsearch": ["dirsearch"],
    "paramspider": ["paramspider"],
    "nuclei": ["nuclei"],
    "httpx": ["httpx"],
    "subfinder": ["subfinder"],
}


# ============================================================================
# Data Classes
# ============================================================================

class ToolType(Enum):
    VULNERABILITY_SCANNER = "Vuln Scanner"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS Detection"
    NETWORK = "Network Scan"
    FUZZER = "Fuzzer"
    RECON = "Recon"


@dataclass
class SecurityTool:
    name: str
    repo: str
    tool_type: ToolType
    description: str
    install_cmd: str
    install_cmd_win: str
    run_cmd: str
    run_cmd_win: str
    update_cmd: str
    update_cmd_win: str
    version_cmd: str
    version_cmd_win: str
    installed: bool = False
    local_version: str = ""
    latest_version: str = ""
    last_updated: str = ""
    install_path: Path = None
    requires_go: bool = False


@dataclass
class ToolExecutionResult:
    tool_name: str
    command: str
    success: bool
    output: str
    error: str
    execution_time: float
    findings: list = field(default_factory=list)


# ============================================================================
# ToolRegistry - Windows/Linux Compatible Tool List
# ============================================================================

class ToolRegistry:
    
    @staticmethod
    def get_all_tools() -> dict[str, SecurityTool]:
        
        tools = {
            # SQLMap - SQL Injection (Python only)
            "sqlmap": SecurityTool(
                name="SQLMap",
                repo="sqlmapproject/sqlmap",
                tool_type=ToolType.SQL_INJECTION,
                description="Automatic SQL Injection detection and exploitation tool",
                install_cmd='git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "{path}"',
                run_cmd=f'{PYTHON_CMD} "{{path}}/sqlmap.py" -u "{{target}}" --batch',
                update_cmd='cd "{path}" && git pull',
                version_cmd=f'{PYTHON_CMD} "{{path}}/sqlmap.py" --version',
                install_cmd_win='git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "{path}"',
                run_cmd_win='python "{path}\\sqlmap.py" -u "{target}" --batch',
                update_cmd_win='cd /d "{path}" && git pull',
                version_cmd_win='python "{path}\\sqlmap.py" --version',
                install_path=TOOLS_BASE_DIR / "sqlmap",
                requires_go=False,
            ),
            
            # XSStrike - XSS Detection (Python only)
            "xsstrike": SecurityTool(
                name="XSStrike",
                repo="s0md3v/XSStrike",
                tool_type=ToolType.XSS,
                description="Advanced XSS detection tool (run via python xsstrike.py)",
                install_cmd='git clone --depth 1 https://github.com/s0md3v/XSStrike.git "{path}"',
                run_cmd=f'{PYTHON_CMD} "{{path}}/xsstrike.py" -u "{{target}}"',
                update_cmd='cd "{path}" && git pull',
                version_cmd=f'{PYTHON_CMD} "{{path}}/xsstrike.py" -h',
                install_cmd_win='git clone --depth 1 https://github.com/s0md3v/XSStrike.git "{path}"',
                run_cmd_win='python "{path}\\xsstrike.py" -u "{target}"',
                update_cmd_win='cd /d "{path}" && git pull',
                version_cmd_win='python "{path}\\xsstrike.py" -h',
                install_path=TOOLS_BASE_DIR / "XSStrike",
                requires_go=False,
            ),
            
            # Dirsearch - Directory bruteforce (Python only)
            "dirsearch": SecurityTool(
                name="Dirsearch",
                repo="maurosoria/dirsearch",
                tool_type=ToolType.RECON,
                description="Web path bruteforce tool",
                install_cmd='git clone --depth 1 https://github.com/maurosoria/dirsearch.git "{path}" && pip install -r "{path}/requirements.txt"',
                run_cmd=f'{PYTHON_CMD} "{{path}}/dirsearch.py" -u "{{target}}"',
                update_cmd='cd "{path}" && git pull',
                version_cmd=f'{PYTHON_CMD} "{{path}}/dirsearch.py" --version',
                install_cmd_win='git clone --depth 1 https://github.com/maurosoria/dirsearch.git "{path}" && pip install -r "{path}\\requirements.txt"',
                run_cmd_win='python "{path}\\dirsearch.py" -u "{target}"',
                update_cmd_win='cd /d "{path}" && git pull',
                version_cmd_win='python "{path}\\dirsearch.py" --version',
                install_path=TOOLS_BASE_DIR / "dirsearch",
                requires_go=False,
            ),
            
            # ParamSpider - Parameter collection (Python only)
            "paramspider": SecurityTool(
                name="ParamSpider",
                repo="devanshbatham/ParamSpider",
                tool_type=ToolType.RECON,
                description="Mining URLs from web archives for parameter discovery",
                install_cmd=f'git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git "{{path}}" && PYTHONUTF8=1 {PYTHON_CMD} -m pip install "{{path}}"',
                run_cmd=f'{PYTHON_CMD} -m paramspider.main -d "{{target}}"',
                update_cmd=f'cd "{{path}}" && git pull && PYTHONUTF8=1 {PYTHON_CMD} -m pip install --upgrade "{{path}}"',
                version_cmd='cd "{path}" && git rev-parse --short HEAD',
                install_cmd_win='git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git "{path}" && set PYTHONUTF8=1&& python -m pip install "{path}"',
                run_cmd_win='python -m paramspider.main -d "{target}"',
                update_cmd_win='cd /d "{path}" && git pull && set PYTHONUTF8=1&& python -m pip install --upgrade "{path}"',
                version_cmd_win='cd /d "{path}" && git rev-parse --short HEAD',
                install_path=TOOLS_BASE_DIR / "ParamSpider",
                requires_go=False,
            ),
            
            # Nuclei Templates - CVE templates (Git only)
            "nuclei-templates": SecurityTool(
                name="Nuclei Templates",
                repo="projectdiscovery/nuclei-templates",
                tool_type=ToolType.VULNERABILITY_SCANNER,
                description="Nuclei vulnerability templates (CVE, misconfigs, etc.)",
                install_cmd='git clone https://github.com/projectdiscovery/nuclei-templates.git "{path}"',
                run_cmd="",
                update_cmd='cd "{path}" && git pull',
                version_cmd='cd "{path}" && git rev-parse --short HEAD',
                install_cmd_win='git clone https://github.com/projectdiscovery/nuclei-templates.git "{path}"',
                run_cmd_win="",
                update_cmd_win='cd /d "{path}" && git pull',
                version_cmd_win='cd /d "{path}" && git rev-parse --short HEAD',
                install_path=TOOLS_BASE_DIR / "nuclei-templates",
                requires_go=False,
            ),
            
            # Nuclei - CVE Scanner (Go required)
            "nuclei": SecurityTool(
                name="Nuclei",
                repo="projectdiscovery/nuclei",
                tool_type=ToolType.VULNERABILITY_SCANNER,
                description="Fast and customizable vulnerability scanner (Go required)",
                install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                run_cmd='nuclei -u "{target}"',
                update_cmd="nuclei -ut",
                version_cmd="nuclei -version",
                install_cmd_win="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                run_cmd_win="nuclei -u {target}",
                update_cmd_win="nuclei -ut",
                version_cmd_win="nuclei -version",
                install_path=TOOLS_BASE_DIR / "nuclei",
                requires_go=True,
            ),
            
            # httpx - HTTP probe (Go required)
            "httpx": SecurityTool(
                name="httpx",
                repo="projectdiscovery/httpx",
                tool_type=ToolType.RECON,
                description="Fast HTTP probe tool (Go required)",
                install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                run_cmd='echo "{target}" | httpx -tech-detect',
                update_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                version_cmd="httpx -version",
                install_cmd_win="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                run_cmd_win="httpx -u {target} -tech-detect -silent",
                update_cmd_win="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                version_cmd_win="httpx -version",
                install_path=TOOLS_BASE_DIR / "httpx",
                requires_go=True,
            ),
            
            # Subfinder - Subdomain discovery (Go required)
            "subfinder": SecurityTool(
                name="Subfinder",
                repo="projectdiscovery/subfinder",
                tool_type=ToolType.RECON,
                description="Fast subdomain discovery tool (Go required)",
                install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                run_cmd='subfinder -d "{target}"',
                update_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                version_cmd="subfinder -version",
                install_cmd_win="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                run_cmd_win="subfinder -d {target}",
                update_cmd_win="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                version_cmd_win="subfinder -version",
                install_path=TOOLS_BASE_DIR / "subfinder",
                requires_go=True,
            ),
            
            # Nmap Vulners - Network vulnerability scripts
            "nmap-vulners": SecurityTool(
                name="Nmap Vulners",
                repo="vulnersCom/nmap-vulners",
                tool_type=ToolType.NETWORK,
                description="Nmap vulnerability detection scripts (Nmap required)",
                install_cmd='git clone https://github.com/vulnersCom/nmap-vulners.git "{path}"',
                run_cmd='nmap -sV --script="{path}/vulners.nse" "{target}"',
                update_cmd='cd "{path}" && git pull',
                version_cmd='cd "{path}" && git rev-parse --short HEAD',
                install_cmd_win='git clone https://github.com/vulnersCom/nmap-vulners.git "{path}"',
                run_cmd_win='nmap -sV --script="{path}\\vulners.nse" {target}',
                update_cmd_win='cd /d "{path}" && git pull',
                version_cmd_win='cd /d "{path}" && git rev-parse --short HEAD',
                install_path=TOOLS_BASE_DIR / "nmap-vulners",
                requires_go=False,
            ),
        }
        
        return tools


# ============================================================================
# GitHubChecker
# ============================================================================

class GitHubChecker:
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        
    async def get_latest_release(self, repo: str) -> dict:
        url = f"{self.api_base}/repos/{repo}/releases/latest"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            session = await self._get_session()
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "version": data.get("tag_name", ""),
                        "published_at": data.get("published_at", ""),
                        "html_url": data.get("html_url", ""),
                        "body": data.get("body", "")[:500]
                    }
                elif response.status == 404:
                    return await self.get_latest_commit(repo)
                else:
                    return {}
        except Exception as e:
            print(f"   [!] GitHub connection failed: {e}")
            return {}
    
    async def get_latest_commit(self, repo: str) -> dict:
        url = f"{self.api_base}/repos/{repo}/commits"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            session = await self._get_session()
            async with session.get(url, headers=headers, params={"per_page": 1}) as response:
                if response.status == 200:
                    data = await response.json()
                    if data:
                        commit = data[0]
                        return {
                            "version": commit["sha"][:7],
                            "published_at": commit["commit"]["committer"]["date"],
                            "html_url": commit["html_url"],
                            "body": commit["commit"]["message"][:200]
                        }
                return {}
        except Exception as e:
            return {}
    
    async def check_for_updates(self, tool: SecurityTool) -> tuple[bool, str, str]:
        print(f"   [*] Checking latest version for {tool.name}...")
        
        latest = await self.get_latest_release(tool.repo)
        
        if not latest:
            return False, "", "Could not fetch version info"
        
        latest_version = latest.get("version", "")
        
        if tool.local_version and tool.local_version == latest_version:
            return False, latest_version, "Already up to date"
        
        release_info = f"Latest: {latest_version} (Current: {tool.local_version or 'Not installed'})"
        
        return True, latest_version, release_info


# ============================================================================
# ToolUpdater
# ============================================================================

class ToolUpdater:
    
    def __init__(self):
        self.github_checker = GitHubChecker()
        self.tools = ToolRegistry.get_all_tools()
        self.state_file = TOOLS_BASE_DIR / "tool_state.json"
        self._load_state()
        self._sync_installed_state()
    
    async def close(self):
        await self.github_checker.close()

    def _path_has_content(self, path: Optional[Path]) -> bool:
        if not path or not path.exists():
            return False
        try:
            next(path.iterdir())
            return True
        except StopIteration:
            return False
        except OSError:
            return False

    def _command_exists(self, tool_name: str, tool: SecurityTool) -> bool:
        candidates = TOOL_COMMAND_ALIASES.get(tool_name)
        if not candidates:
            normalized_name = tool.name.lower().replace(" ", "")
            candidates = [tool_name, normalized_name]
        return any(shutil.which(cmd) for cmd in candidates)

    def _is_tool_available(self, tool_name: str, tool: SecurityTool) -> bool:
        if "git clone" in tool.install_cmd:
            if not tool.install_path or not tool.install_path.exists():
                return False

            required_files = TOOL_REQUIRED_FILES.get(tool_name, [])
            if required_files:
                return all((tool.install_path / rel_path).exists() for rel_path in required_files)

            return self._path_has_content(tool.install_path)

        if "pip install" in tool.install_cmd or tool.requires_go:
            return self._command_exists(tool_name, tool)

        if tool.install_path:
            return tool.install_path.exists()

        return False

    def _sync_installed_state(self):
        state_changed = False
        for tool_name, tool in self.tools.items():
            actual_installed = self._is_tool_available(tool_name, tool)
            if tool.installed != actual_installed:
                tool.installed = actual_installed
                if not actual_installed:
                    tool.local_version = ""
                    tool.last_updated = ""
                state_changed = True
        if state_changed:
            self._save_state()
    
    def _load_state(self):
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    
                for tool_name, tool_state in state.items():
                    if tool_name in self.tools:
                        tool = self.tools[tool_name]
                        tool.installed = tool_state.get('installed', False)
                        tool.local_version = tool_state.get('local_version', '')
                        tool.last_updated = tool_state.get('last_updated', '')
            except Exception as e:
                print(f"[!] Failed to load state: {e}")
    
    def _save_state(self):
        state = {}
        for name, tool in self.tools.items():
            state[name] = {
                'installed': tool.installed,
                'local_version': tool.local_version,
                'last_updated': tool.last_updated
            }
        
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
    
    def _get_command(self, tool: SecurityTool, cmd_type: str) -> str:
        if IS_WINDOWS:
            cmd_map = {
                'install': tool.install_cmd_win,
                'run': tool.run_cmd_win,
                'update': tool.update_cmd_win,
                'version': tool.version_cmd_win
            }
        else:
            cmd_map = {
                'install': tool.install_cmd,
                'run': tool.run_cmd,
                'update': tool.update_cmd,
                'version': tool.version_cmd
            }
        return cmd_map.get(cmd_type, '')
    
    def _run_command(self, cmd: str, cwd: str = None, timeout: int = 300) -> tuple[bool, str, str]:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore',
                stdin=subprocess.DEVNULL
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command execution timed out"
        except Exception as e:
            return False, "", str(e)
    
    def _check_requirements(self, tool: SecurityTool) -> tuple[bool, str]:
        success, _, _ = self._run_command("git --version")
        if not success:
            return False, "Git is not installed. https://git-scm.com/download/win"
        
        if tool.requires_go:
            success, _, _ = self._run_command("go version")
            if not success:
                return False, "Go is not installed. https://go.dev/dl/"
        
        
        return True, "OK"
    
    async def install_tool(self, tool_name: str) -> bool:
        if tool_name not in self.tools:
            print(f"[X] Unknown tool: {tool_name}")
            print(f"   Available tools: {', '.join(self.tools.keys())}")
            return False
        
        tool = self.tools[tool_name]
        print(f"\n[*] Installing {tool.name}...")
        print(f"   Description: {tool.description}")
        
        ok, msg = self._check_requirements(tool)
        if not ok:
            print(f"   [X] {msg}")
            return False
        
        # Check if already installed
        if self._is_tool_available(tool_name, tool):
            if tool.install_path:
                print(f"   [!] Already installed: {tool.install_path}")
            else:
                print("   [!] Already installed (found on PATH)")
            tool.installed = True
            tool.local_version = await self._get_local_version(tool)
            if not tool.last_updated:
                tool.last_updated = datetime.now().isoformat()
            self._save_state()
            return True

        # Remove broken git clone directories before reinstalling.
        if "git clone" in tool.install_cmd and tool.install_path and tool.install_path.exists():
            print(f"   [!] Found incomplete installation at {tool.install_path}. Reinstalling...")
            try:
                shutil.rmtree(tool.install_path)
            except Exception as e:
                print(f"   [X] Failed to clean old install directory: {e}")
                return False
        
        install_cmd = self._get_command(tool, 'install')
        install_cmd = install_cmd.format(path=tool.install_path)
        
        print(f"   Running: {install_cmd[:80]}...")
        
        # For git clone, run in TOOLS_BASE_DIR
        if "git clone" in install_cmd:
            cwd = str(TOOLS_BASE_DIR)
        else:
            cwd = None
        
        success, stdout, stderr = self._run_command(install_cmd, cwd=cwd, timeout=600)
        
        # Success requires a usable install, not just a created directory.
        is_success = success and self._is_tool_available(tool_name, tool)
        
        if is_success:
            tool.installed = True
            tool.last_updated = datetime.now().isoformat()
            
            version = await self._get_local_version(tool)
            tool.local_version = version
            
            self._save_state()
            print(f"   [OK] {tool.name} installed successfully! (Version: {version})")
            return True
        else:
            print(f"   [X] Installation failed: {stderr[:300]}")
            if stdout:
                print(f"   Output: {stdout[:200]}")
            return False
    
    async def update_tool(self, tool_name: str) -> bool:
        if tool_name not in self.tools:
            print(f"[X] Unknown tool: {tool_name}")
            return False
        
        tool = self.tools[tool_name]
        
        if not self._is_tool_available(tool_name, tool):
            tool.installed = False
            self._save_state()
            print(f"[!] {tool.name} is not installed or installation is incomplete.")
            return await self.install_tool(tool_name)

        tool.installed = True
        
        print(f"\n[*] Checking updates for {tool.name}...")
        
        needs_update, latest_version, info = await self.github_checker.check_for_updates(tool)
        
        if not needs_update:
            print(f"   [OK] {info}")
            return True
        
        print(f"   [*] Update found! {info}")
        
        update_cmd = self._get_command(tool, 'update')
        update_cmd = update_cmd.format(path=tool.install_path)
        
        print(f"   Running: {update_cmd}")
        
        success, stdout, stderr = self._run_command(
            update_cmd, 
            cwd=str(tool.install_path) if tool.install_path and tool.install_path.exists() else None
        )
        
        if success:
            tool.local_version = latest_version
            tool.latest_version = latest_version
            tool.last_updated = datetime.now().isoformat()
            self._save_state()
            print(f"   [OK] {tool.name} updated! (Version: {latest_version})")
            return True
        else:
            print(f"   [X] Update failed: {stderr[:200]}")
            return False
    
    async def _get_local_version(self, tool: SecurityTool) -> str:
        version_cmd = self._get_command(tool, 'version')
        if not version_cmd:
            return "unknown"
        
        version_cmd = version_cmd.format(path=tool.install_path)
        success, stdout, stderr = self._run_command(version_cmd)
        
        if success:
            version_patterns = [
                r'v?(\d+\.\d+\.\d+)',
                r'version[:\s]+(\S+)',
                r'^([a-f0-9]{7,40})\s*$'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, stdout + stderr, re.IGNORECASE | re.MULTILINE)
                if match:
                    ver = match.group(1)
                    # Truncate full git SHA to short hash
                    if re.fullmatch(r'[a-f0-9]{8,40}', ver):
                        return ver[:7]
                    return ver
            
            return stdout.strip()[:20] if stdout else "installed"
        
        return "unknown"
    
    async def update_all_tools(self) -> dict:
        print("\n" + "="*60)
        print("[*] Updating all tools")
        print("="*60)
        
        results = {}
        
        for tool_name, tool in self.tools.items():
            if tool.installed:
                results[tool_name] = await self.update_tool(tool_name)
        
        print("\n" + "="*60)
        print("[*] Update Results:")
        for name, success in results.items():
            status = "[OK]" if success else "[X]"
            print(f"   {status} {name}")
        print("="*60)
        
        return results
    
    async def check_all_updates(self) -> list[dict]:
        print("\n[*] Checking update status...")
        
        updates_available = []
        
        for tool_name, tool in self.tools.items():
            needs_update, latest, info = await self.github_checker.check_for_updates(tool)
            
            if needs_update:
                updates_available.append({
                    'name': tool.name,
                    'tool_key': tool_name,
                    'current': tool.local_version,
                    'latest': latest,
                    'info': info
                })
        
        return updates_available
    
    def get_tool_status(self) -> list[dict]:
        status_list = []
        
        for name, tool in self.tools.items():
            requirements = []
            if tool.requires_go:
                requirements.append("Go")
            req_str = f" ({', '.join(requirements)} required)" if requirements else ""
            
            status_list.append({
                'name': tool.name,
                'key': name,
                'type': tool.tool_type.value,
                'installed': tool.installed,
                'version': tool.local_version or 'N/A',
                'last_updated': tool.last_updated or 'Never',
                'description': tool.description,
                'requirements': req_str
            })
        
        return status_list


# ============================================================================
# AIToolSelector
# ============================================================================

class AIToolSelector:
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = None
        self.tool_updater = ToolUpdater()
        
        if self.api_key and anthropic:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            print("[OK] AI Tool Selector ready")
        else:
            print("[!] No API key - Using rule-based selection")
    
    def _get_available_tools_info(self) -> str:
        info = "Available security tools:\n\n"
        
        for name, tool in self.tool_updater.tools.items():
            status = "[OK] Installed" if tool.installed else "[X] Not installed"
            info += f"- {tool.name} ({name}): {tool.description}\n"
            info += f"  Type: {tool.tool_type.value} | Status: {status}\n\n"
        
        return info
    
    async def analyze_target(self, target: str, initial_info: str = "") -> dict:
        if not self.client:
            return self._rule_based_selection(target, initial_info)
        
        tools_info = self._get_available_tools_info()
        
        prompt = f"""You are a senior security engineer.
Create a vulnerability scanning strategy for the target.

## Target: {target}
## Additional Info: {initial_info or "None"}

## {tools_info}

Respond ONLY in the following JSON format:
{{
    "observation": "Observation about the target",
    "thoughts": "Your analysis thoughts",
    "recommended_tools": [
        {{
            "order": 1,
            "tool": "tool name",
            "reason": "Selection reason",
            "command": "Execution command"
        }}
    ],
    "scan_strategy": "Overall strategy",
    "estimated_time": "Estimated time"
}}"""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1:
                return json.loads(response_text[json_start:json_end])
            
        except Exception as e:
            print(f"[!] AI analysis failed: {e}")
        
        return self._rule_based_selection(target, initial_info)
    
    def _rule_based_selection(self, target: str, initial_info: str) -> dict:
        tools = []
        
        tools.append({
            "order": 1,
            "tool": "dirsearch",
            "reason": "Hidden path detection",
            "command": f"python dirsearch.py -u {target}"
        })
        
        if "?" in target or "login" in target.lower():
            tools.append({
                "order": 2,
                "tool": "sqlmap",
                "reason": "SQL Injection testing",
                "command": f"python sqlmap.py -u {target} --batch"
            })
        
        tools.append({
            "order": 3,
            "tool": "xsstrike",
            "reason": "XSS vulnerability testing",
            "command": f"python xsstrike.py -u {target}"
        })
        
        return {
            "observation": f"Target URL: {target}",
            "thoughts": "Rule-based analysis (No AI)",
            "recommended_tools": tools,
            "scan_strategy": "Path discovery -> SQLi -> XSS",
            "estimated_time": "About 10-30 minutes"
        }


# ============================================================================
# ToolExecutor
# ============================================================================

class ToolExecutor:
    
    def __init__(self):
        self.tool_updater = ToolUpdater()
    
    def execute(self, tool_name: str, target: str, extra_args: str = "") -> ToolExecutionResult:
        import time
        
        if tool_name not in self.tool_updater.tools:
            return ToolExecutionResult(
                tool_name=tool_name,
                command="",
                success=False,
                output="",
                error=f"Unknown tool: {tool_name}",
                execution_time=0
            )
        
        tool = self.tool_updater.tools[tool_name]
        
        if not tool.installed:
            return ToolExecutionResult(
                tool_name=tool_name,
                command="",
                success=False,
                output="",
                error=f"{tool.name} is not installed",
                execution_time=0
            )

        if not self.tool_updater._is_tool_available(tool_name, tool):
            tool.installed = False
            self.tool_updater._save_state()
            return ToolExecutionResult(
                tool_name=tool_name,
                command="",
                success=False,
                output="",
                error=(
                    f"{tool.name} installation is incomplete. "
                    f"Run: python tool_manager.py install {tool_name}"
                ),
                execution_time=0
            )
        
        # Build command with proper quoting for paths with spaces
        format_vars = {
            'path': str(tool.install_path),
            'target': target,
        }
        
        if IS_WINDOWS:
            command = tool.run_cmd_win.format(**format_vars)
        else:
            command = tool.run_cmd.format(**format_vars)
        
        # Clean up double spaces
        command = command.replace("  ", " ").strip()
        
        if extra_args:
            command += f" {extra_args}"
        
        print(f"\n[>] Running {tool.name}...")
        print(f"   Command: {command}")
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600,
                encoding='utf-8',
                errors='ignore',
                stdin=subprocess.DEVNULL
            )
            
            execution_time = time.time() - start_time
            
            findings_input = result.stdout if result.returncode == 0 else ""
            findings = self._extract_findings(tool_name, findings_input)
            
            return ToolExecutionResult(
                tool_name=tool_name,
                command=command,
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                execution_time=execution_time,
                findings=findings
            )
            
        except subprocess.TimeoutExpired:
            return ToolExecutionResult(
                tool_name=tool_name,
                command=command,
                success=False,
                output="",
                error="Execution timed out (10 minutes)",
                execution_time=600
            )
        except Exception as e:
            return ToolExecutionResult(
                tool_name=tool_name,
                command=command,
                success=False,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def _extract_findings(self, tool_name: str, output: str) -> list:
        findings = []
        
        if tool_name == "nuclei":
            pattern = r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]'
            matches = re.findall(pattern, output)
            for template_id, protocol, severity in matches:
                findings.append({
                    "severity": severity,
                    "id": template_id,
                    "protocol": protocol
                })
        
        elif tool_name == "sqlmap":
            if "is vulnerable" in output.lower():
                findings.append({
                    "severity": "HIGH",
                    "id": "SQL Injection",
                    "detail": "SQL Injection vulnerability found"
                })
            if "parameter" in output.lower() and "injectable" in output.lower():
                findings.append({
                    "severity": "HIGH",
                    "id": "SQL Injection",
                    "detail": "Injectable parameter found"
                })
        
        elif tool_name == "xsstrike":
            lowered = output.lower()
            xss_indicators = [
                "vulnerable",
                "xss found",
                "possible xss",
                "confirmed xss",
                "payload was successful",
                "payloads were successful",
            ]
            if any(indicator in lowered for indicator in xss_indicators):
                findings.append({
                    "severity": "MEDIUM",
                    "id": "XSS",
                    "detail": "XSS vulnerability found"
                })
        
        return findings


# ============================================================================
# CLI Interface
# ============================================================================

async def _auto_install_go() -> bool:
    """Auto-install Go if not found. Returns True if Go is available after."""
    print("\n[*] Go not found. Attempting automatic installation...")
    
    if IS_WINDOWS:
        go_version = "1.23.6"
        msi = f"go{go_version}.windows-amd64.msi"
        url = f"https://go.dev/dl/{msi}"
        cmds = [
            f'powershell -Command "Invoke-WebRequest -Uri \'{url}\' -OutFile \'%TEMP%\\{msi}\'"',
            f'msiexec /i "%TEMP%\\{msi}" /quiet /norestart',
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                print(f"   [X] Go installation failed: {result.stderr[:200]}")
                return False
        # Update PATH for this process
        go_path = r"C:\Program Files\Go\bin"
        os.environ["PATH"] = go_path + os.pathsep + os.environ.get("PATH", "")
    else:
        import struct
        go_version = "1.23.6"
        arch_map = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv6l"}
        machine = platform.machine()
        go_arch = arch_map.get(machine, "amd64")
        go_tar = f"go{go_version}.linux-{go_arch}.tar.gz"
        url = f"https://go.dev/dl/{go_tar}"
        
        cmds = [
            f'curl -fsSL "{url}" -o "/tmp/{go_tar}"',
            f'rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/{go_tar}"',
            f'rm -f "/tmp/{go_tar}"',
        ]
        for cmd in cmds:
            print(f"   Running: {cmd[:80]}...")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                print(f"   [X] Go installation failed: {result.stderr[:200]}")
                return False
        
        # Update PATH for this process
        os.environ["PATH"] = f"/usr/local/go/bin:{Path.home()}/go/bin:" + os.environ.get("PATH", "")
    
    if shutil.which("go"):
        result = subprocess.run("go version", shell=True, capture_output=True, text=True)
        print(f"   [OK] {result.stdout.strip()}")
        return True
    else:
        print("   [X] Go installed but not found in PATH")
        return False


async def main():
    
    print("""
+==============================================================+
|          AI Security Tool Arsenal Manager                    |
+==============================================================+
|  Commands:                                                   |
|    list        - Show all tools status                       |
|    install     - Install tool (e.g., install sqlmap)         |
|    install-all - Install all available tools                 |
|    update      - Update tool (e.g., update sqlmap)           |
|    update-all  - Update all tools                            |
|    check       - Check for available updates                 |
|    scan        - AI-guided scan                              |
+==============================================================+
""")
    
    if len(sys.argv) < 2:
        print("Usage: python tool_manager.py <command> [options]")
        print("Example: python tool_manager.py list")
        return
    
    command = sys.argv[1].lower()
    updater = ToolUpdater()
    
    try:
        await _run_command(command, updater)
    finally:
        await updater.close()


async def _run_command(command: str, updater: ToolUpdater):
    # list
    if command == "list":
        status = updater.get_tool_status()
        
        print("\n[*] Security Tools List")
        print("=" * 95)
        print(f"{'Name':<18} {'Type':<15} {'Status':<10} {'Version':<12} {'Requirements':<20}")
        print("-" * 95)
        
        for tool in status:
            status_icon = "[OK]" if tool['installed'] else "[X]"
            print(f"{tool['name']:<18} {tool['type']:<15} {status_icon:<10} {tool['version']:<12} {tool['requirements']:<20}")
        
        print("=" * 95)
        print(f"\n[*] Recommended for Windows: sqlmap, xsstrike, dirsearch (Python only)")
    
    # install
    elif command == "install":
        if len(sys.argv) < 3:
            print("Usage: python tool_manager.py install <tool_name>")
            print("\nRecommended (Python only):")
            print("  python tool_manager.py install sqlmap")
            print("  python tool_manager.py install xsstrike")
            print("  python tool_manager.py install dirsearch")
            return
        
        tool_name = sys.argv[2].lower()
        await updater.install_tool(tool_name)
    
    # install-all
    elif command == "install-all":
        print("\n[*] Installing all available tools...")
        has_go = bool(shutil.which("go"))
        
        # Auto-install Go if missing
        if not has_go:
            has_go = await _auto_install_go()
        
        for tool_name, tool in updater.tools.items():
            if tool.requires_go and not has_go:
                print(f"\n[!] Skipping {tool.name} (requires Go - auto-install failed)")
                continue
            await updater.install_tool(tool_name)
        
        print("\n[OK] install-all complete.")
    
    # update
    elif command == "update":
        if len(sys.argv) < 3:
            print("Usage: python tool_manager.py update <tool_name>")
            return
        
        tool_name = sys.argv[2].lower()
        await updater.update_tool(tool_name)
    
    # update-all
    elif command == "update-all":
        await updater.update_all_tools()
    
    # check
    elif command == "check":
        updates = await updater.check_all_updates()
        
        if updates:
            print("\n[*] Updates available:")
            for u in updates:
                print(f"   - {u['name']}: {u['current']} -> {u['latest']}")
        else:
            print("\n[OK] All tools are up to date!")
    
    # scan
    elif command == "scan":
        if len(sys.argv) < 3:
            print("Usage: python tool_manager.py scan <target_url>")
            return
        
        target = sys.argv[2]
        
        selector = AIToolSelector()
        analysis = await selector.analyze_target(target)
        
        print("\n" + "="*60)
        print("[*] AI Analysis Results")
        print("="*60)
        print(f"\n[Observation] {analysis.get('observation', 'N/A')}")
        print(f"\n[Thoughts] {analysis.get('thoughts', 'N/A')}")
        print(f"\n[Strategy] {analysis.get('scan_strategy', 'N/A')}")
        
        print("\n[Recommended Tools]")
        for tool in analysis.get('recommended_tools', []):
            print(f"\n   {tool.get('order', '?')}. {tool.get('tool', 'unknown')}")
            print(f"      Reason: {tool.get('reason', 'N/A')}")
        
        print("\n" + "="*60)
        
        answer = input("\nStart scanning with this strategy? (y/n): ").lower()
        
        if answer == 'y':
            executor = ToolExecutor()
            all_findings = []
            
            for tool_info in analysis.get('recommended_tools', []):
                tool_name = tool_info.get('tool', '')
                
                if tool_name in updater.tools and updater.tools[tool_name].installed:
                    result = executor.execute(tool_name, target)
                    
                    print(f"\n{'='*60}")
                    print(f"[*] {tool_name} Results:")
                    print(f"   Status: {'[OK]' if result.success else '[X]'}")
                    print(f"   Execution Time: {result.execution_time:.2f}s")
                    
                    # Show findings
                    if result.findings:
                        print(f"   [!] Findings:")
                        for f in result.findings:
                            print(f"      - [{f.get('severity', 'INFO').upper()}] {f.get('id', 'unknown')}")
                            all_findings.append(f)
                    
                    # Show errors (if failed)
                    if result.error and not result.success:
                        print(f"   [X] Errors:")
                        for line in result.error.strip().split('\n')[:10]:
                            if line.strip():
                                print(f"      {line}")
                    
                    # Show full output (if success)
                    if result.output and result.success:
                        print(f"   [*] Output:")
                        print("-" * 60)
                        lines = [l for l in result.output.strip().split('\n') if l.strip()]
                        for line in lines:
                            print(f"   {line}")
                        print("-" * 60)
                else:
                    print(f"\n[!] {tool_name} is not installed. Skipping...")
            
            # Summary
            print("\n" + "="*60)
            print("[*] SCAN SUMMARY")
            print("="*60)
            print(f"   Target: {target}")
            print(f"   Total Findings: {len(all_findings)}")
            
            if all_findings:
                critical = len([f for f in all_findings if f.get('severity', '').upper() in ['CRITICAL', 'HIGH']])
                medium = len([f for f in all_findings if f.get('severity', '').upper() == 'MEDIUM'])
                low = len([f for f in all_findings if f.get('severity', '').upper() in ['LOW', 'INFO']])
                
                print(f"   Critical/High: {critical}")
                print(f"   Medium: {medium}")
                print(f"   Low/Info: {low}")
                
                print("\n   [!] Vulnerabilities Found:")
                for f in all_findings:
                    print(f"      - [{f.get('severity', 'INFO').upper()}] {f.get('id', 'unknown')}")
            else:
                print("   No vulnerabilities found.")
            
            print("="*60)
    
    else:
        print(f"[X] Unknown command: {command}")


if __name__ == '__main__':
    asyncio.run(main())
