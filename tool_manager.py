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
# 📦 설정 및 데이터 클래스
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
