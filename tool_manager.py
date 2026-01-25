import asyncio
import json
import os
import subprocess
import shutil
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from enum import Enum
import aiohttp
import anthropic



# ════════════════════════════════════════════════════════════════════════════
#  설정 및 데이터 클래스
# ════════════════════════════════════════════════════════════════════════════

# 툴 저장 기본 경로
TOOLS_BASE_DIR = Path.home() / ".ai_security_tools"
TOOLS_BASE_DIR.mkdir(exist_ok=True)


class ToolType(Enum):
    """툴 유형"""
    VULNERABILITY_SCANNER = "취약점 스캐너"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS 탐지"
    NETWORK = "네트워크 스캔"
    FUZZER = "퍼저"
    RECON = "정보 수집"


@dataclass
class SecurityTool:
    """
    보안 툴 정보
    
    각 오픈소스 툴의 정보를 담는 상자예요.
    """
    name: str                    # 툴 이름
    repo: str                    # GitHub 저장소 (owner/repo)
    tool_type: ToolType          # 툴 유형
    description: str             # 설명
    install_cmd: str             # 설치 명령어
    run_cmd: str                 # 실행 명령어 템플릿
    update_cmd: str              # 업데이트 명령어
    version_cmd: str             # 버전 확인 명령어
    installed: bool = False      # 설치 여부
    local_version: str = ""      # 로컬 버전
    latest_version: str = ""     # 최신 버전
    last_updated: str = ""       # 마지막 업데이트 시간
    install_path: Path = None    # 설치 경로


@dataclass
class ToolExecutionResult:
    """툴 실행 결과"""
    tool_name: str
    command: str
    success: bool
    output: str
    error: str
    execution_time: float
    findings: list = field(default_factory=list)

# ════════════════════════════════════════════════════════════════════════════
#  ToolRegistry - 지원하는 툴 목록
# ════════════════════════════════════════════════════════════════════════════

class ToolRegistry:
    """
    지원하는 보안 툴 레지스트리
    
    여기에 새로운 툴을 추가하면 시스템이 자동으로 관리해요!
    """
    
    @staticmethod
    def get_all_tools() -> dict[str, SecurityTool]:
        """모든 지원 툴 반환"""
        
        tools = {
            # ─────────────────────────────────────────────────
            # Nuclei - 가장 중요! CVE 템플릿 기반 스캐너
            # ─────────────────────────────────────────────────
            "nuclei": SecurityTool(
                name="Nuclei",
                repo="projectdiscovery/nuclei",
                tool_type=ToolType.VULNERABILITY_SCANNER,
                description="빠르고 커스터마이징 가능한 취약점 스캐너. 매일 새로운 CVE 템플릿이 추가됨!",
                install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                run_cmd="nuclei -u {target} -t {template}",
                update_cmd="nuclei -ut",  # 템플릿 업데이트
                version_cmd="nuclei -version",
                install_path=TOOLS_BASE_DIR / "nuclei"
            ),
            
            # Nuclei 템플릿 (별도 관리)
            "nuclei-templates": SecurityTool(
                name="Nuclei Templates",
                repo="projectdiscovery/nuclei-templates",
                tool_type=ToolType.VULNERABILITY_SCANNER,
                description="Nuclei용 취약점 템플릿 모음. CVE, 잘못된 설정, 노출된 패널 등",
                install_cmd="git clone https://github.com/projectdiscovery/nuclei-templates.git",
                run_cmd="",  # 직접 실행 안함
                update_cmd="cd {path} && git pull",
                version_cmd="cd {path} && git log -1 --format=%H",
                install_path=TOOLS_BASE_DIR / "nuclei-templates"
            ),
            
            # ─────────────────────────────────────────────────
            # SQLMap - SQL Injection 전문 도구
            # ─────────────────────────────────────────────────
            "sqlmap": SecurityTool(
                name="SQLMap",
                repo="sqlmapproject/sqlmap",
                tool_type=ToolType.SQL_INJECTION,
                description="자동 SQL Injection 탐지 및 익스플로잇 도구",
                install_cmd="git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git",
                run_cmd="python {path}/sqlmap.py -u {target} --batch",
                update_cmd="cd {path} && git pull",
                version_cmd="python {path}/sqlmap.py --version",
                install_path=TOOLS_BASE_DIR / "sqlmap"
            ),
            
            # ─────────────────────────────────────────────────
            # XSStrike - XSS 전문 도구
            # ─────────────────────────────────────────────────
            "xsstrike": SecurityTool(
                name="XSStrike",
                repo="s0md3v/XSStrike",
                tool_type=ToolType.XSS,
                description="고급 XSS 탐지 및 익스플로잇 도구",
                install_cmd="git clone https://github.com/s0md3v/XSStrike.git && pip install -r XSStrike/requirements.txt",
                run_cmd="python {path}/xsstrike.py -u {target}",
                update_cmd="cd {path} && git pull",
                version_cmd="python {path}/xsstrike.py --help | head -5",
                install_path=TOOLS_BASE_DIR / "XSStrike"
            ),
            
            # ─────────────────────────────────────────────────
            # Nmap Scripts - 네트워크 스캔 스크립트
            # ─────────────────────────────────────────────────
            "nmap-vulners": SecurityTool(
                name="Nmap Vulners",
                repo="vulnersCom/nmap-vulners",
                tool_type=ToolType.NETWORK,
                description="Nmap용 취약점 탐지 스크립트",
                install_cmd="git clone https://github.com/vulnersCom/nmap-vulners.git",
                run_cmd="nmap -sV --script={path}/vulners.nse {target}",
                update_cmd="cd {path} && git pull",
                version_cmd="cd {path} && git log -1 --format=%H",
                install_path=TOOLS_BASE_DIR / "nmap-vulners"
            ),
            
            # ─────────────────────────────────────────────────
            # Nikto - 웹서버 스캐너
            # ─────────────────────────────────────────────────
            "nikto": SecurityTool(
                name="Nikto",
                repo="sullo/nikto",
                tool_type=ToolType.VULNERABILITY_SCANNER,
                description="웹서버 취약점 스캐너",
                install_cmd="git clone https://github.com/sullo/nikto.git",
                run_cmd="perl {path}/program/nikto.pl -h {target}",
                update_cmd="cd {path} && git pull",
                version_cmd="perl {path}/program/nikto.pl -Version",
                install_path=TOOLS_BASE_DIR / "nikto"
            ),
            
            # ─────────────────────────────────────────────────
            # Subfinder - 서브도메인 탐지
            # ─────────────────────────────────────────────────
            "subfinder": SecurityTool(
                name="Subfinder",
                repo="projectdiscovery/subfinder",
                tool_type=ToolType.RECON,
                description="빠른 서브도메인 탐지 도구",
                install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                run_cmd="subfinder -d {target}",
                update_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                version_cmd="subfinder -version",
                install_path=TOOLS_BASE_DIR / "subfinder"
            ),
            
            # ─────────────────────────────────────────────────
            # httpx - HTTP 프로브
            # ─────────────────────────────────────────────────
            "httpx": SecurityTool(
                name="httpx",
                repo="projectdiscovery/httpx",
                tool_type=ToolType.RECON,
                description="빠른 HTTP 프로브 도구. 기술 스택 탐지",
                install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                run_cmd="echo {target} | httpx -tech-detect",
                update_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                version_cmd="httpx -version",
                install_path=TOOLS_BASE_DIR / "httpx"
            ),
            
            # ─────────────────────────────────────────────────
            # Dirsearch - 디렉토리 브루트포스
            # ─────────────────────────────────────────────────
            "dirsearch": SecurityTool(
                name="Dirsearch",
                repo="maurosoria/dirsearch",
                tool_type=ToolType.RECON,
                description="웹 경로 브루트포스 도구",
                install_cmd="git clone https://github.com/maurosoria/dirsearch.git && pip install -r dirsearch/requirements.txt",
                run_cmd="python {path}/dirsearch.py -u {target}",
                update_cmd="cd {path} && git pull",
                version_cmd="python {path}/dirsearch.py --version",
                install_path=TOOLS_BASE_DIR / "dirsearch"
            ),
            
            # ─────────────────────────────────────────────────
            # Paramspider - 파라미터 수집
            # ─────────────────────────────────────────────────
            "paramspider": SecurityTool(
                name="ParamSpider",
                repo="devanshbatham/ParamSpider",
                tool_type=ToolType.RECON,
                description="웹 아카이브에서 파라미터 URL 수집",
                install_cmd="git clone https://github.com/devanshbatham/ParamSpider.git && pip install -r ParamSpider/requirements.txt",
                run_cmd="python {path}/paramspider.py -d {target}",
                update_cmd="cd {path} && git pull",
                version_cmd="cd {path} && git log -1 --format=%H",
                install_path=TOOLS_BASE_DIR / "ParamSpider"
            ),
        }
        
        return tools

# ════════════════════════════════════════════════════════════════════════════
#  GitHubChecker - GitHub에서 최신 버전 확인
# ════════════════════════════════════════════════════════════════════════════

class GitHubChecker:
    """
    GitHub API를 사용해서 최신 버전을 확인하는 클래스
    
    [작동 방식]
    1. GitHub API에 요청 보내기
    2. 최신 릴리즈 또는 커밋 정보 가져오기
    3. 로컬 버전과 비교
    4. 업데이트 필요 여부 반환
    """
    
    def __init__(self, github_token: Optional[str] = None):
        """
        github_token: GitHub API 토큰 (선택사항, 없으면 rate limit 낮음)
        """
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"
        
    async def get_latest_release(self, repo: str) -> dict:
        """
        저장소의 최신 릴리즈 정보 가져오기
        
        repo: "owner/repo" 형식 (예: "projectdiscovery/nuclei")
        """
        url = f"{self.api_base}/repos/{repo}/releases/latest"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "version": data.get("tag_name", ""),
                            "published_at": data.get("published_at", ""),
                            "html_url": data.get("html_url", ""),
                            "body": data.get("body", "")[:500]  # 릴리즈 노트
                        }
                    elif response.status == 404:
                        # 릴리즈가 없으면 최신 커밋 확인
                        return await self.get_latest_commit(repo)
                    else:
                        print(f"    GitHub API 오류: {response.status}")
                        return {}
        except Exception as e:
            print(f"    GitHub 연결 실패: {e}")
            return {}
    
    async def get_latest_commit(self, repo: str) -> dict:
        """최신 커밋 정보 가져오기"""
        url = f"{self.api_base}/repos/{repo}/commits"
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        try:
            async with aiohttp.ClientSession() as session:
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
            print(f"    커밋 정보 가져오기 실패: {e}")
            return {}
    
    async def check_for_updates(self, tool: SecurityTool) -> tuple[bool, str, str]:
        """
        업데이트 필요 여부 확인
        
        Returns:
            (needs_update, latest_version, release_info)
        """
        print(f"    {tool.name} 최신 버전 확인 중...")
        
        latest = await self.get_latest_release(tool.repo)
        
        if not latest:
            return False, "", "버전 정보를 가져올 수 없습니다"
        
        latest_version = latest.get("version", "")
        
        # 로컬 버전과 비교
        if tool.local_version and tool.local_version == latest_version:
            return False, latest_version, "이미 최신 버전입니다"
        
        release_info = f"최신: {latest_version} (현재: {tool.local_version or '미설치'})"
        if latest.get("body"):
            release_info += f"\n변경사항: {latest['body'][:100]}..."
        
        return True, latest_version, release_info

# ════════════════════════════════════════════════════════════════════════════
#  ToolUpdater - 툴 설치 및 업데이트
# ════════════════════════════════════════════════════════════════════════════

class ToolUpdater:
    """
    보안 툴 설치 및 업데이트 관리자
    
    [주요 기능]
    1. 툴 설치
    2. 툴 업데이트
    3. 버전 확인
    4. 상태 저장/로드
    """
    
    def __init__(self):
        self.github_checker = GitHubChecker()
        self.tools = ToolRegistry.get_all_tools()
        self.state_file = TOOLS_BASE_DIR / "tool_state.json"
        self._load_state()
    
    def _load_state(self):
        """저장된 툴 상태 로드"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    
                for tool_name, tool_state in state.items():
                    if tool_name in self.tools:
                        self.tools[tool_name].installed = tool_state.get('installed', False)
                        self.tools[tool_name].local_version = tool_state.get('local_version', '')
                        self.tools[tool_name].last_updated = tool_state.get('last_updated', '')
            except Exception as e:
                print(f" 상태 로드 실패: {e}")
    
    def _save_state(self):
        """툴 상태 저장"""
        state = {}
        for name, tool in self.tools.items():
            state[name] = {
                'installed': tool.installed,
                'local_version': tool.local_version,
                'last_updated': tool.last_updated
            }
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _run_command(self, cmd: str, cwd: str = None, timeout: int = 300) -> tuple[bool, str, str]:
        """
        쉘 명령어 실행
        
        Returns:
            (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "명령어 실행 시간 초과"
        except Exception as e:
            return False, "", str(e)
    
    async def install_tool(self, tool_name: str) -> bool:
        """
        툴 설치
        
        [설치 과정]
        1. 이미 설치되었는지 확인
        2. 설치 명령어 실행
        3. 설치 확인
        4. 상태 저장
        """
        if tool_name not in self.tools:
            print(f" 알 수 없는 툴: {tool_name}")
            return False
        
        tool = self.tools[tool_name]
        print(f"\n {tool.name} 설치 중...")
        print(f"   설명: {tool.description}")
        
        # 설치 디렉토리 생성
        if tool.install_path:
            tool.install_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 설치 명령어에 경로 대입
        install_cmd = tool.install_cmd.format(path=tool.install_path)
        
        # git clone인 경우 디렉토리로 이동
        if "git clone" in install_cmd:
            cwd = str(TOOLS_BASE_DIR)
        else:
            cwd = None
        
        print(f"   실행: {install_cmd[:80]}...")
        success, stdout, stderr = self._run_command(install_cmd, cwd=cwd)
        
        if success or (tool.install_path and tool.install_path.exists()):
            tool.installed = True
            tool.last_updated = datetime.now().isoformat()
            
            # 버전 확인
            version = await self._get_local_version(tool)
            tool.local_version = version
            
            self._save_state()
            print(f"   {tool.name} 설치 완료! (버전: {version})")
            return True
        else:
            print(f"   설치 실패: {stderr[:200]}")
            return False
    
    async def update_tool(self, tool_name: str) -> bool:
        """
        툴 업데이트
        
        [업데이트 과정]
        1. 최신 버전 확인
        2. 업데이트 필요 여부 판단
        3. 업데이트 명령어 실행
        4. 상태 저장
        """
        if tool_name not in self.tools:
            print(f"알 수 없는 툴: {tool_name}")
            return False
        
        tool = self.tools[tool_name]
        
        if not tool.installed:
            print(f"{tool.name}이(가) 설치되어 있지 않습니다. 먼저 설치하세요.")
            return await self.install_tool(tool_name)
        
        print(f"\n{tool.name} 업데이트 확인 중...")
        
        # 최신 버전 확인
        needs_update, latest_version, info = await self.github_checker.check_for_updates(tool)
        
        if not needs_update:
            print(f"   {info}")
            return True
        
        print(f"   업데이트 발견! {info}")
        
        # 업데이트 명령어 실행
        update_cmd = tool.update_cmd.format(path=tool.install_path)
        print(f"   실행: {update_cmd}")
        
        success, stdout, stderr = self._run_command(update_cmd, cwd=str(tool.install_path) if tool.install_path else None)
        
        if success:
            tool.local_version = latest_version
            tool.latest_version = latest_version
            tool.last_updated = datetime.now().isoformat()
            self._save_state()
            print(f"    {tool.name} 업데이트 완료! (버전: {latest_version})")
            return True
        else:
            print(f"    업데이트 실패: {stderr[:200]}")
            return False
    
    async def _get_local_version(self, tool: SecurityTool) -> str:
        """로컬 설치된 툴의 버전 확인"""
        if not tool.version_cmd:
            return "unknown"
        
        version_cmd = tool.version_cmd.format(path=tool.install_path)
        success, stdout, stderr = self._run_command(version_cmd)
        
        if success:
            # 버전 번호 추출 시도
            version_patterns = [
                r'v?(\d+\.\d+\.\d+)',
                r'version[:\s]+(\S+)',
                r'^([a-f0-9]{7,40})$'  # git commit hash
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, stdout + stderr, re.IGNORECASE | re.MULTILINE)
                if match:
                    return match.group(1)
            
            return stdout.strip()[:20] if stdout else "installed"
        
        return "unknown"
    
    async def update_all_tools(self) -> dict:
        """모든 설치된 툴 업데이트"""
        print("\n" + "="*60)
        print(" 모든 툴 업데이트 시작")
        print("="*60)
        
        results = {}
        
        for tool_name, tool in self.tools.items():
            if tool.installed:
                results[tool_name] = await self.update_tool(tool_name)
        
        print("\n" + "="*60)
        print("업데이트 결과:")
        for name, success in results.items():
            status = "success" if success else "fail"
            print(f"   {status} {name}")
        print("="*60)
        
        return results
    
    async def check_all_updates(self) -> list[dict]:
        """모든 툴의 업데이트 상태 확인 (업데이트 없이)"""
        print("\n 업데이트 상태 확인 중...")
        
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
        """모든 툴의 상태 반환"""
        status_list = []
        
        for name, tool in self.tools.items():
            status_list.append({
                'name': tool.name,
                'key': name,
                'type': tool.tool_type.value,
                'installed': tool.installed,
                'version': tool.local_version or 'N/A',
                'last_updated': tool.last_updated or 'Never',
                'description': tool.description
            })
        
        return status_list


# ════════════════════════════════════════════════════════════════════════════
# AIToolSelector - AI가 상황에 맞는 툴 선택 (ReAct)
# ════════════════════════════════════════════════════════════════════════════

class AIToolSelector:
    """
    AI 기반 툴 선택기 (ReAct 프레임워크)
    
    [ReAct 동작 방식]
    1. 관찰(Observation): 타겟 정보 수집
    2. 생각(Thought): 어떤 툴이 필요한지 판단
    3. 행동(Action): 툴 실행
    4. 분석(Analysis): 결과 분석 및 다음 단계 결정
    
    [예시]
    관찰: "이 사이트는 PHP를 쓰고 로그인 폼이 있어"
    생각: "PHP 관련 CVE 확인하고, 로그인 폼은 SQLi 테스트해야겠다"
    행동: nuclei로 PHP CVE 스캔, sqlmap으로 로그인 테스트
    분석: "PHP-CGI 취약점 발견! SQLi는 없음"
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = None
        self.tool_updater = ToolUpdater()
        
        if self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            print(" AI 툴 선택기 준비 완료")
        else:
            print(" API 키 없음 - 기본 규칙 기반 선택 사용")
    
    def _get_available_tools_info(self) -> str:
        """AI에게 제공할 툴 목록 정보"""
        info = "사용 가능한 보안 도구:\n\n"
        
        for name, tool in self.tool_updater.tools.items():
            status = " 설치됨" if tool.installed else "needs installation"
            info += f"- {tool.name} ({name}): {tool.description}\n"
            info += f"  유형: {tool.tool_type.value} | 상태: {status}\n"
            info += f"  실행: {tool.run_cmd}\n\n"
        
        return info
    
    async def analyze_target(self, target: str, initial_info: str = "") -> dict:
        """
        타겟을 분석하고 적절한 툴과 전략 추천
        
        target: 스캔 대상 URL
        initial_info: 이미 알고 있는 정보 (기술 스택 등)
        
        Returns:
            {
                "observation": "관찰 내용",
                "thoughts": "AI의 생각",
                "recommended_tools": [{"tool": "nuclei", "reason": "...", "command": "..."}],
                "scan_strategy": "스캔 전략"
            }
        """
        if not self.client:
            return self._rule_based_selection(target, initial_info)
        
        tools_info = self._get_available_tools_info()
        
        prompt = f"""당신은 10년 경력의 시니어 보안 엔지니어입니다.
주어진 타겟에 대해 취약점 스캔 전략을 수립해야 합니다.

## 타겟 정보
- URL: {target}
- 추가 정보: {initial_info or "없음"}

## {tools_info}

## 지시사항
ReAct(Reasoning + Acting) 프레임워크를 사용하여 분석하세요:

1. **관찰(Observation)**: 타겟 URL에서 알 수 있는 정보를 나열하세요
   - 도메인, 경로, 파라미터
   - 예상되는 기술 스택
   - 잠재적 공격 표면

2. **생각(Thought)**: 어떤 취약점을 테스트해야 하는지 추론하세요
   - URL 구조 기반 추론
   - 기술 스택 기반 추론
   - 일반적인 웹 취약점

3. **행동 계획(Action Plan)**: 사용할 툴과 순서를 결정하세요
   - 정보 수집 → 취약점 스캔 → 심층 테스트 순서로
   - 각 툴의 구체적인 명령어 포함

반드시 아래 JSON 형식으로만 응답하세요:
{{
    "observation": "관찰 내용 (타겟에서 파악한 정보)",
    "thoughts": "생각 (왜 이 툴들이 필요한지)",
    "recommended_tools": [
        {{
            "order": 1,
            "tool": "툴 이름 (예: nuclei)",
            "reason": "이 툴을 선택한 이유",
            "command": "실행할 명령어",
            "expected_findings": "예상되는 발견 사항"
        }}
    ],
    "scan_strategy": "전체 스캔 전략 요약",
    "estimated_time": "예상 소요 시간"
}}

최소 3개, 최대 6개의 툴을 추천하세요."""

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
            print(f"⚠️ AI 분석 실패: {e}")
        
        return self._rule_based_selection(target, initial_info)
    
    def _rule_based_selection(self, target: str, initial_info: str) -> dict:
        """규칙 기반 툴 선택 (AI 없을 때 폴백)"""
        tools = []
        
        # 1. 정보 수집
        tools.append({
            "order": 1,
            "tool": "httpx",
            "reason": "기술 스택 탐지",
            "command": f"echo {target} | httpx -tech-detect",
            "expected_findings": "웹 서버, 프레임워크 정보"
        })
        
        # 2. 디렉토리 스캔
        tools.append({
            "order": 2,
            "tool": "dirsearch",
            "reason": "숨겨진 경로 탐지",
            "command": f"python dirsearch.py -u {target}",
            "expected_findings": "관리자 페이지, 백업 파일 등"
        })
        
        # 3. 취약점 스캔
        tools.append({
            "order": 3,
            "tool": "nuclei",
            "reason": "알려진 CVE 탐지",
            "command": f"nuclei -u {target} -t cves/",
            "expected_findings": "CVE 취약점"
        })
        
        # 4. SQL Injection (파라미터가 있으면)
        if "?" in target or "login" in target.lower() or "search" in target.lower():
            tools.append({
                "order": 4,
                "tool": "sqlmap",
                "reason": "SQL Injection 테스트",
                "command": f"python sqlmap.py -u {target} --batch",
                "expected_findings": "SQL Injection 취약점"
            })
        
        return {
            "observation": f"타겟 URL: {target}",
            "thoughts": "기본 규칙 기반 분석 (AI 미사용)",
            "recommended_tools": tools,
            "scan_strategy": "정보수집 → 경로탐지 → 취약점스캔 순서",
            "estimated_time": "약 10-30분"
        }


# ════════════════════════════════════════════════════════════════════════════
# ToolExecutor - 툴 실행기
# ════════════════════════════════════════════════════════════════════════════

class ToolExecutor:
    """
    보안 툴 실행기
    
    AI가 선택한 툴을 실제로 실행하고 결과를 수집해요.
    """
    
    def __init__(self):
        self.tool_updater = ToolUpdater()
    
    def execute(self, tool_name: str, target: str, extra_args: str = "") -> ToolExecutionResult:
        """
        툴 실행
        
        tool_name: 실행할 툴 이름
        target: 스캔 대상
        extra_args: 추가 인자
        """
        import time
        
        if tool_name not in self.tool_updater.tools:
            return ToolExecutionResult(
                tool_name=tool_name,
                command="",
                success=False,
                output="",
                error=f"알 수 없는 툴: {tool_name}",
                execution_time=0
            )
        
        tool = self.tool_updater.tools[tool_name]
        
        if not tool.installed:
            return ToolExecutionResult(
                tool_name=tool_name,
                command="",
                success=False,
                output="",
                error=f"{tool.name}이(가) 설치되어 있지 않습니다",
                execution_time=0
            )
        
        # 명령어 구성
        command = tool.run_cmd.format(
            path=tool.install_path,
            target=target
        )
        
        if extra_args:
            command += f" {extra_args}"
        
        print(f"\n🚀 {tool.name} 실행 중...")
        print(f"   명령어: {command}")
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600  # 10분 타임아웃
            )
            
            execution_time = time.time() - start_time
            
            # 결과에서 주요 발견사항 추출
            findings = self._extract_findings(tool_name, result.stdout + result.stderr)
            
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
                error="실행 시간 초과 (10분)",
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
        """툴 출력에서 주요 발견사항 추출"""
        findings = []
        
        # Nuclei 결과 파싱
        if tool_name == "nuclei":
            # [critical] [cve-2021-xxxx] ...
            pattern = r'\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]'
            matches = re.findall(pattern, output, re.IGNORECASE)
            for severity, vuln_id in matches:
                findings.append({
                    "severity": severity,
                    "id": vuln_id
                })
        
        # SQLMap 결과 파싱
        elif tool_name == "sqlmap":
            if "is vulnerable" in output.lower():
                findings.append({
                    "severity": "high",
                    "id": "SQL Injection",
                    "detail": "SQL Injection 취약점 발견"
                })
        
        # Nikto 결과 파싱
        elif tool_name == "nikto":
            pattern = r'\+ (OSVDB-\d+|CVE-\d+-\d+):'
            matches = re.findall(pattern, output)
            for vuln_id in matches:
                findings.append({
                    "severity": "medium",
                    "id": vuln_id
                })
        
        return findings


# ════════════════════════════════════════════════════════════════════════════
# UpdateScheduler - 자동 업데이트 스케줄러
# ════════════════════════════════════════════════════════════════════════════

class UpdateScheduler:
    """
    자동 업데이트 스케줄러
    
    주기적으로 툴을 업데이트하는 스케줄러예요.
    """
    
    def __init__(self, tool_updater: ToolUpdater):
        self.tool_updater = tool_updater
        self.running = False
    
    async def start(self, interval_hours: int = 24):
        """
        스케줄러 시작
        
        interval_hours: 업데이트 주기 (기본 24시간)
        """
        self.running = True
        print(f"자동 업데이트 스케줄러 시작 (주기: {interval_hours}시간)")
        
        while self.running:
            try:
                # 업데이트 확인 및 실행
                await self.tool_updater.update_all_tools()
            except Exception as e:
                print(f"스케줄러 오류: {e}")
            
            # 다음 업데이트까지 대기
            await asyncio.sleep(interval_hours * 3600)
    
    def stop(self):
        """스케줄러 중지"""
        self.running = False
        print(" 자동 업데이트 스케줄러 중지")


# ════════════════════════════════════════════════════════════════════════════
# 🎮 CLI 인터페이스
# ════════════════════════════════════════════════════════════════════════════

async def main():
    """메인 CLI 인터페이스"""
    import sys
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║          AI 보안 툴 자동 관리 시스템                       ║
╠══════════════════════════════════════════════════════════════╣
║  사용법:                                                     ║
║    python tool_manager.py <명령어> [옵션]                    ║
║                                                              ║
║  명령어:                                                     ║
║    list        - 모든 툴 상태 보기                           ║
║    install     - 툴 설치 (예: install nuclei)                ║
║    update      - 툴 업데이트 (예: update sqlmap)             ║
║    update-all  - 모든 툴 업데이트                            ║
║    check       - 업데이트 가능 여부 확인                     ║
║    scan        - AI가 타겟 분석 후 스캔 (예: scan http://x)  ║
║                                                              ║
║  예시:                                                       ║
║    python tool_manager.py list                               ║
║    python tool_manager.py install nuclei                     ║
║    python tool_manager.py scan http://testsite.com           ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        return
    
    command = sys.argv[1].lower()
    updater = ToolUpdater()
    
    # ─────────────────────────────────────
    # list - 툴 상태 보기
    # ─────────────────────────────────────
    if command == "list":
        status = updater.get_tool_status()
        
        print("\n보안 툴 목록")
        print("=" * 80)
        print(f"{'이름':<20} {'유형':<15} {'상태':<10} {'버전':<15} {'마지막 업데이트':<20}")
        print("-" * 80)
        
        for tool in status:
            status_icon = "success" if tool['installed'] else "need update"
            print(f"{tool['name']:<20} {tool['type']:<15} {status_icon:<10} {tool['version']:<15} {tool['last_updated'][:19] if tool['last_updated'] != 'Never' else 'Never':<20}")
        
        print("=" * 80)
    
    # ─────────────────────────────────────
    # install - 툴 설치
    # ─────────────────────────────────────
    elif command == "install":
        if len(sys.argv) < 3:
            print("사용법: python tool_manager.py install <tool_name>")
            print("예시: python tool_manager.py install nuclei")
            return
        
        tool_name = sys.argv[2].lower()
        await updater.install_tool(tool_name)
    
    # ─────────────────────────────────────
    # update - 툴 업데이트
    # ─────────────────────────────────────
    elif command == "update":
        if len(sys.argv) < 3:
            print("사용법: python tool_manager.py update <tool_name>")
            return
        
        tool_name = sys.argv[2].lower()
        await updater.update_tool(tool_name)
    
    # ─────────────────────────────────────
    # update-all - 모든 툴 업데이트
    # ─────────────────────────────────────
    elif command == "update-all":
        await updater.update_all_tools()
    
    # ─────────────────────────────────────
    # check - 업데이트 확인
    # ─────────────────────────────────────
    elif command == "check":
        updates = await updater.check_all_updates()
        
        if updates:
            print("\n업데이트 가능한 툴:")
            for u in updates:
                print(f"   • {u['name']}: {u['current']} → {u['latest']}")
        else:
            print("\n모든 툴이 최신 버전입니다!")
    
    # ─────────────────────────────────────
    # scan - AI 분석 후 스캔
    # ─────────────────────────────────────
    elif command == "scan":
        if len(sys.argv) < 3:
            print("사용법: python tool_manager.py scan <target_url>")
            return
        
        target = sys.argv[2]
        
        # AI 분석
        selector = AIToolSelector()
        analysis = await selector.analyze_target(target)
        
        print("\n" + "="*60)
        print(" AI 분석 결과")
        print("="*60)
        print(f"\n 관찰: {analysis.get('observation', 'N/A')}")
        print(f"\n 생각: {analysis.get('thoughts', 'N/A')}")
        print(f"\n 전략: {analysis.get('scan_strategy', 'N/A')}")
        print(f"\n 예상 시간: {analysis.get('estimated_time', 'N/A')}")
        
        print("\n🔧 추천 툴:")
        for tool in analysis.get('recommended_tools', []):
            print(f"\n   {tool.get('order', '?')}. {tool.get('tool', 'unknown')}")
            print(f"      이유: {tool.get('reason', 'N/A')}")
            print(f"      명령어: {tool.get('command', 'N/A')}")
        
        print("\n" + "="*60)
        
        # 실행 여부 확인
        answer = input("\n이 전략으로 스캔을 시작할까요? (y/n): ").lower()
        
        if answer == 'y':
            executor = ToolExecutor()
            
            for tool_info in analysis.get('recommended_tools', []):
                tool_name = tool_info.get('tool', '')
                
                if tool_name in updater.tools and updater.tools[tool_name].installed:
                    result = executor.execute(tool_name, target)
                    
                    print(f"\n{'='*40}")
                    print(f"{tool_name} 결과:")
                    print(f"   성공: {'success' if result.success else 'fail'}")
                    print(f"   실행 시간: {result.execution_time:.2f}초")
                    
                    if result.findings:
                        print(f"   발견 사항:")
                        for f in result.findings:
                            print(f"      • [{f.get('severity', 'info')}] {f.get('id', 'unknown')}")
                else:
                    print(f"\n{tool_name}이(가) 설치되어 있지 않습니다. 건너뜁니다.")
    
    else:
        print(f"fail 알 수 없는 명령어: {command}")


if __name__ == '__main__':
    asyncio.run(main())