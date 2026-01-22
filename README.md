---

### 1. English Version (`README.md`)

```markdown
# AI-Powered Vulnerability Scanner & Tool Manager

An intelligent security orchestration engine that automatically updates open-source tools and executes context-aware penetration testing using AI reasoning (ReAct).

## 🚀 Quick Start

### 1. View Tool Status
```bash
python tool_manager.py list

```

### 2. Update All Tools (Automation)

```bash
python tool_manager.py update-all

```

### 3. AI-Driven Scan

```bash
python tool_manager.py scan [http://target.com](http://target.com)

```

## 📋 Supported Tool Arsenal (Auto-Updated)

Our AI engine utilizes the latest versions of these industry-standard tools:

| Tool | Purpose | Update Method |
| --- | --- | --- |
| **Nuclei** | Template-based CVE Scanning | `nuclei -ut` (Daily) |
| **Nuclei Templates** | Massive CVE Template Library | `git pull` |
| **SQLMap** | SQL Injection Exploitation | `git pull` |
| **XSStrike** | Advanced XSS Detection | `git pull` |
| **Nikto** | Web Server Vulnerability Scan | `git pull` |
| **Nmap Vulners** | Network & Service Vulnerabilities | `nmap --script-updatedb` |
| **Subfinder** | Subdomain Enumeration | `go install` |
| **httpx** | Technology Stack Fingerprinting | `go install` |
| **Dirsearch** | Web Path/Directory Brute-forcing | `git pull` |
| **ParamSpider** | URL Parameter Discovery | `git pull` |

## ⚖️ License

This project is licensed under the **GNU GPL v3.0**.

## ⚠️ Legal Disclaimer

This tool is for **educational and authorized testing only**. The developer (rkdeornr0414) is not responsible for any misuse. Unauthorized scanning is strictly prohibited.

```

---

### 2. 한국어 버전 (`README.ko.md`)

```markdown
# AI 기반 취약점 통합 탐색기 및 툴 매니저

AI의 추론 능력(ReAct)을 활용하여 타겟 웹사이트에 최적화된 공격 시나리오를 설계하고, 최신 보안 도구들을 자동 업데이트 및 실행하는 지능형 보안 엔진입니다.

## 🚀 빠른 시작 가이드

### 1. 모든 툴 상태 보기
```bash
python tool_manager.py list

```

### 2. 모든 툴 업데이트 (자동화)

```bash
python tool_manager.py update-all

```

### 3. 🌟 AI 자동 분석 및 스캔

```bash
python tool_manager.py scan [http://target.com](http://target.com)

```

## 📋 지원하는 툴 무기고 (자동 업데이트)

본 엔진은 AI가 실시간으로 분석한 결과에 따라 아래의 최신 보안 도구들을 선택적으로 사용합니다.

| 툴 이름 | 용도 | 업데이트 방식 |
| --- | --- | --- |
| **Nuclei** | CVE 취약점 스캔 | ✅ `nuclei -ut` (매일 최신화) |
| **Nuclei Templates** | CVE 템플릿 모음 | ✅ `git pull` 연동 |
| **SQLMap** | SQL 인젝션 테스트 | ✅ `git pull` 연동 |
| **XSStrike** | 지능형 XSS 탐지 | ✅ `git pull` 연동 |
| **Nikto** | 웹 서버 취약점 스캔 | ✅ `git pull` 연동 |
| **Nmap Vulners** | 네트워크 취약점 탐지 | ✅ `nmap` 스크립트 DB 업데이트 |
| **Subfinder** | 서브도메인 탐지 | ✅ `go install` 최신 버전 |
| **httpx** | 기술 스택 분석 | ✅ `go install` 최신 버전 |
| **Dirsearch** | 디렉토리/경로 탐색 | ✅ `git pull` 연동 |
| **ParamSpider** | 파라미터 수집 | ✅ `git pull` 연동 |

## ⚖️ 라이선스 (License)

본 프로젝트는 **GNU GPL v3.0** 라이선스를 따릅니다. 오픈소스 정신에 따라 수정 및 배포 시 소스 코드를 공개해야 합니다.

## ⚠️ 법적 고지 (Legal Disclaimer)

본 도구는 **교육적 목적 및 사전 승인된 보안 테스트**만을 위해 개발되었습니다. 개발자(rkdeornr0414)는 본 도구의 오용으로 인한 법적 책임이나 피해에 대해 책임을 지지 않습니다. 무단 스캔은 불법이며, 승인된 타겟에 대해서만 사용하십시오.

```

---
