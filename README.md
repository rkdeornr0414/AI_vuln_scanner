# AI-Powered Vulnerability Scanner & Tool Manager

An intelligent security orchestration engine that automatically updates open-source tools and executes context-aware penetration testing using AI reasoning (ReAct).

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/rkdeornr0414/AI_vuln_scanner.git
cd AI_vuln_scanner
```

**Linux / macOS:**
```bash
./setup.sh
source .venv/bin/activate
```

**Windows:**
```cmd
setup.bat
.venv\Scripts\activate.bat
```

### 2. Install Tools

```bash
python tool_manager.py install-all    # Install all available tools
python tool_manager.py install sqlmap  # Or install individually
```

### 3. Use

```bash
python tool_manager.py list           # Show all tools & status
python tool_manager.py update-all     # Update all installed tools
python tool_manager.py check          # Check for available updates
python tool_manager.py scan http://target.com  # AI-guided scan
```

### 4. AI Features (Optional)

Set your Anthropic API key to enable AI-powered scan analysis:

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # Linux/macOS
set ANTHROPIC_API_KEY=sk-ant-...           # Windows
```

---

## 📋 Supported Tool Arsenal (Auto-Updated)

| Tool | Purpose | Update Method |
| --- | --- | --- |
| **Nuclei** | Template-based CVE Scanning | `nuclei -ut` (Daily) |
| **Nuclei Templates** | Massive CVE Template Library | `git pull` |
| **SQLMap** | SQL Injection Exploitation | `git pull` |
| **XSStrike** | Advanced XSS Detection | `git pull` |
| **Nmap Vulners** | Network & Service Vulnerabilities | `nmap` script DB update |
| **Subfinder** | Subdomain Enumeration | `go install` |
| **httpx** | Technology Stack Fingerprinting | `go install` |
| **Dirsearch** | Web Path/Directory Brute-forcing | `pip install --upgrade` |
| **ParamSpider** | URL Parameter Discovery | `pip install --upgrade` |

## ⚖️ License

This project is licensed under the **GNU GPL v3.0**.

## ⚠️ Legal Disclaimer

This tool is for **educational and authorized testing only**. The developer (rkdeornr0414) is not responsible for any misuse. Unauthorized scanning is strictly prohibited.

---

# AI 기반 취약점 통합 탐색기 및 툴 매니저

AI의 추론 능력(ReAct)을 활용하여 타겟 웹사이트에 최적화된 공격 시나리오를 설계하고, 최신 보안 도구들을 자동 업데이트 및 실행하는 지능형 보안 엔진입니다.

## 🚀 빠른 시작 가이드

### 1. 클론 & 설정

```bash
git clone https://github.com/rkdeornr0414/AI_vuln_scanner.git
cd AI_vuln_scanner
```

**Linux / macOS:**
```bash
./setup.sh
source .venv/bin/activate
```

**Windows:**
```cmd
setup.bat
.venv\Scripts\activate.bat
```

### 2. 도구 설치

```bash
python tool_manager.py install-all    # 모든 도구 설치
python tool_manager.py install sqlmap  # 개별 설치
```

### 3. 사용

```bash
python tool_manager.py list           # 모든 도구 상태 보기
python tool_manager.py update-all     # 모든 도구 업데이트
python tool_manager.py check          # 업데이트 확인
python tool_manager.py scan http://target.com  # AI 자동 분석 및 스캔
```

### 4. AI 기능 (선택)

AI 분석 기능을 사용하려면 Anthropic API 키를 설정하세요:

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # Linux/macOS
set ANTHROPIC_API_KEY=sk-ant-...           # Windows
```

## 📋 지원하는 툴 무기고 (자동 업데이트)

| 툴 이름 | 용도 | 업데이트 방식 |
| --- | --- | --- |
| **Nuclei** | CVE 취약점 스캔 | ✅ `nuclei -ut` (매일 최신화) |
| **Nuclei Templates** | CVE 템플릿 모음 | ✅ `git pull` 연동 |
| **SQLMap** | SQL 인젝션 테스트 | ✅ `git pull` 연동 |
| **XSStrike** | 지능형 XSS 탐지 | ✅ `git pull` 연동 |
| **Nmap Vulners** | 네트워크 취약점 탐지 | ✅ `nmap` 스크립트 DB 업데이트 |
| **Subfinder** | 서브도메인 탐지 | ✅ `go install` 최신 버전 |
| **httpx** | 기술 스택 분석 | ✅ `go install` 최신 버전 |
| **Dirsearch** | 디렉토리/경로 탐색 | ✅ `pip install --upgrade` |
| **ParamSpider** | 파라미터 수집 | ✅ `pip install --upgrade` |

## ⚖️ 라이선스 (License)

본 프로젝트는 **GNU GPL v3.0** 라이선스를 따릅니다.

## ⚠️ 법적 고지 (Legal Disclaimer)

본 도구는 **교육적 목적 및 사전 승인된 보안 테스트**만을 위해 개발되었습니다. 개발자(rkdeornr0414)는 본 도구의 오용으로 인한 법적 책임이나 피해에 대해 책임을 지지 않습니다. 무단 스캔은 불법이며, 승인된 타겟에 대해서만 사용하십시오.
