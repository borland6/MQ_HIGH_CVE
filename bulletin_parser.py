"""
bulletin_parser.py — IBM MQ Security Bulletin 內頁解析器

基於實際頁面結構（IBM Security Bulletin 通用格式）：

頁面文字結構（get_text 後）:
  Vulnerability Details
  CVEID:
  CVE-2026-XXXX
  ...
  CVSS Base score:
  9.3                        ← 直接是數字
  CVSS Vector:
  ...
  （下一個 CVE 重複以上結構）

  Affected Products and Versions
  Affected Product(s)   Version(s)
  IBM MQ                9.3.0 through 9.3.0.40 (LTS)
  IBM MQ                9.3.1 through 9.3.5.1  (CD)
  IBM MQ Bridge...      (略，Bridge to Blockchain 不含入)

  Remediation/Fixes
  ...
  For IBM MQ 9.1 LTS:
    · Apply IBM MQ 9.1.0.37
  For IBM MQ 9.2 LTS:
    · Apply IBM MQ 9.2.0.43
  For IBM MQ 9.3 LTS:
    · Apply IBM MQ 9.3.0.41
  For IBM MQ 9.3 CD, 9.4 LTS, 9.4 CD:
    · Apply IBM MQ 10 (MQ 10 may provide the fix as a CD release)

IBM MQ 版本線規則（第 3 碼判斷）：
  LTS（Long Term Support）： 第 3 碼 = 0，例如 9.3.0.5、9.4.0.1
  CD（Continuous Delivery）： 第 3 碼 ≠ 0，例如 9.3.1.5、9.4.2.3

Fixpack Release Date 取得方式：
  每個版本主幹各有一個 Fix List 頁面，從表格中查詢對應版本的 GA Date：
    9.1 LTS → https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts
    9.2 LTS → https://www.ibm.com/support/pages/fix-list-ibm-mq-version-92-lts
    9.3 LTS → https://www.ibm.com/support/pages/fix-list-ibm-mq-version-93-lts
    9.4 LTS → https://www.ibm.com/support/pages/fix-list-ibm-mq-version-94-lts
"""

import logging
import re
import time
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from models import SecurityBulletin, CveDetail

logger = logging.getLogger(__name__)

WAIT_TIMEOUT = 20

# ──────────────────────────────────────────────────────────────
# 正規表示式常數
# ──────────────────────────────────────────────────────────────

RE_CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# IBM MQ / IBM 產品 iFix 常用前綴（IT 為 MQ 常見，保留 PH/PI/PM 作 fallback）
RE_IFIX = re.compile(r"\b((?:IT|PH|PI|PM|PK|PT|IF)\d{5,})\b", re.IGNORECASE)

RE_QUARTER = re.compile(r"\b([1-4]Q\s*\d{4})\b", re.IGNORECASE)

# IBM MQ 版本號：N.N.N.N（主版本 9 或 10，支援多主幹）
RE_MQ_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")

# LTS：第 3 碼 = 0（例如 9.3.0.5、10.0.0.1）
RE_MQ_LTS_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.0\.\d+)\b")

# CD：第 3 碼 ≠ 0（例如 9.3.1.5、9.4.2.3）
RE_MQ_CD_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.[1-9]\d*\.\d+)\b")

# Apply Fix Pack / Apply IBM MQ 解析（版本號在同一行）
RE_APPLY_FP = re.compile(r"(?:Apply\b.+?|Apply\s+IBM\s+MQ\s+)(\d{1,2}\.\d+\.\d+\.\d+)", re.IGNORECASE)
# LTS 限定（Apply + 第3碼=0）
RE_APPLY_FP_LTS = re.compile(r"(?:Apply\b.+?|Apply\s+IBM\s+MQ\s+)(\d{1,2}\.\d+\.0\.\d+)", re.IGNORECASE)
# CD 限定（Apply + 第3碼≠0）
RE_APPLY_FP_CD = re.compile(r"(?:Apply\b.+?|Apply\s+IBM\s+MQ\s+)(\d{1,2}\.\d+\.[1-9]\d*\.\d+)", re.IGNORECASE)

# Fix List URL 對應表（major.minor → URL）
# LTS 版本用各自主幹頁面；9.4 CD 用 node/7157705
FIX_LIST_URLS: Dict[str, str] = {
    "9.1": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts",
    "9.2": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-92-lts",
    "9.3": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-93-lts",
    "9.4": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-94-lts",
    "9.4_cd": "https://www.ibm.com/support/pages/node/7157705",
}

# ──────────────────────────────────────────────────────────────
# 輔助函式
# ──────────────────────────────────────────────────────────────

def _severity_from_score(score: float) -> str:
    """依 CVSS 分數計算 Severity（Critical >= 9.0, High >= 7.0）。"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return ""


def _is_lts_version(version: str) -> bool:
    """判斷版本號是否為 LTS（第 3 碼 = 0）。"""
    parts = version.split(".")
    return len(parts) == 4 and parts[2] == "0"


def _is_cd_version(version: str) -> bool:
    """判斷版本號是否為 CD（第 3 碼 ≠ 0）。"""
    parts = version.split(".")
    return len(parts) == 4 and parts[2] != "0"


def _major_minor(version: str) -> str:
    """取版本號的「主.次」部分，例如 '9.3.0.41' → '9.3'。"""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return ""


def _wait_for_page_load(driver, timeout: int = WAIT_TIMEOUT):
    """等待內頁主要內容載入。"""
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "article, main, .ibm-content, #content, body")
            )
        )
        time.sleep(1.5)
    except TimeoutException:
        logger.warning("等待頁面載入逾時，嘗試繼續解析")


# ──────────────────────────────────────────────────────────────
# CVE 詳細資訊解析
# ──────────────────────────────────────────────────────────────

def _parse_cve_details(lines: List[str], vd_start: int, vd_end: int) -> List[CveDetail]:
    """
    從 Vulnerability Details 區段解析每個 CVE 的 ID 與 CVSS Base Score。

    頁面文字結構（每個 CVE 區塊）：
      CVEID:
      CVE-XXXX-YYYY
      DESCRIPTION:
      ...
      CVSS Base score:
      9.3              ← 緊接在 "CVSS Base score:" 下一個非空行就是分數
      CVSS Vector:
      ...
    """
    details: List[CveDetail] = []
    vd_lines = lines[vd_start:vd_end]

    current_cve = ""
    expect_score = False  # 下一個數字行是 CVSS Score

    for line in vd_lines:
        stripped = line.strip()
        if not stripped:
            continue

        # 偵測 CVE ID 行
        cve_match = RE_CVE.fullmatch(stripped.upper())
        if cve_match:
            if current_cve and not any(d.cve_id == current_cve for d in details):
                details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))
            current_cve = stripped.upper()
            expect_score = False
            continue

        # 偵測 "CVSS Base score:" 標記
        if re.match(r"CVSS\s+Base\s+score\s*:?$", stripped, re.IGNORECASE):
            expect_score = True
            continue

        # 讀取 CVSS 分數
        if expect_score and current_cve:
            try:
                score = float(stripped)
                severity = _severity_from_score(score)
                details.append(CveDetail(
                    cve_id=current_cve,
                    cvss_score=score,
                    severity=severity,
                ))
                logger.debug("  CVE %s → CVSS %.1f (%s)", current_cve, score, severity)
                current_cve = ""
                expect_score = False
            except ValueError:
                pass
            continue

    if current_cve and not any(d.cve_id == current_cve for d in details):
        details.append(CveDetail(cve_id=current_cve, cvss_score=0.0))

    return details


def _fallback_parse_cve_details(text: str, cve_ids: List[str]) -> List[CveDetail]:
    """當找不到 Vulnerability Details 段落時，直接從全文抓取每個 CVE 的 CVSS。"""
    details: List[CveDetail] = []
    upper_text = text.upper()
    for cve_id in cve_ids:
        idx = upper_text.find(cve_id.upper())
        score = 0.0
        if idx != -1:
            window = text[idx:idx + 1200]
            m = re.search(
                r"CVSS\s*Base\s*score\s*:?[\s\n]*([0-9]+(?:\.[0-9])?)",
                window, re.IGNORECASE
            )
            if m:
                score = float(m.group(1))
        details.append(CveDetail(
            cve_id=cve_id.upper(),
            cvss_score=score,
            severity=_severity_from_score(score)
        ))
    return details


# ──────────────────────────────────────────────────────────────
# Bulletin 類型判斷（LTS / CD / both）
# ──────────────────────────────────────────────────────────────

def _detect_bulletin_type(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    偵測 Bulletin 類型：
      - "lts"：只有 LTS 版本（第 3 碼 = 0）
      - "cd" ：只有 CD 版本（第 3 碼 ≠ 0）
      - "both"：同時包含 LTS 與 CD
    """
    search_end = min(rem_start + 60, len(lines)) if rem_start != -1 else aff_start + 60
    combined_text = "\n".join(lines[aff_start:search_end])

    has_lts = bool(RE_MQ_LTS_VERSION.search(combined_text))
    has_cd = bool(RE_MQ_CD_VERSION.search(combined_text))

    if rem_start != -1:
        rem_text = "\n".join(lines[rem_start:rem_start + 80])
        if re.search(r"LTS|Long\s+Term\s+Support", rem_text, re.IGNORECASE):
            has_lts = True
        if re.search(r"\bCD\b|Continuous\s+Delivery", rem_text, re.IGNORECASE):
            has_cd = True

    if has_lts and has_cd:
        return "both"
    if has_cd:
        return "cd"
    return "lts"


def _fallback_detect_bulletin_type(page_text: str, title: str) -> str:
    """當 Affected Products 區段不存在時，從全文判斷公告類型。"""
    has_lts = bool(RE_MQ_LTS_VERSION.search(page_text))
    has_cd = bool(RE_MQ_CD_VERSION.search(page_text))
    if has_lts and has_cd:
        return "both"
    if has_cd:
        return "cd"
    return "lts"


# ──────────────────────────────────────────────────────────────
# Affected Versions 解析
# ──────────────────────────────────────────────────────────────

# 版本範圍格式：N.N.N.N to/through N.N.N.N（IBM MQ 頁面用 "to"）
# 行尾可能有 "LTS" 或 "CD" 標記，例如：9.1.0.28 to 9.1.0.36 LTS
RE_VERSION_RANGE = re.compile(
    r"(\d{1,2}\.\d+\.\d+(?:\.\d+)?)\s+(?:to|through)\s+(\d{1,2}\.\d+\.\d+\.\d+)"
    r"(?:\s+(LTS|CD))?",
    re.IGNORECASE
)

# 不納入的產品關鍵字（Bridge to Blockchain 等元件）
EXCLUDED_PRODUCT_KEYWORDS = [
    "bridge to blockchain",
    "bridge for salesforce",
    "advanced message security",
    "managed file transfer",
]


def _is_excluded_product(product_line: str) -> bool:
    """
    判斷該產品行是否為不需納入的元件（Bridge to Blockchain 等）。

    IBM MQ Bulletin 實際格式有兩種：
      "IBM MQ - all components except IBM MQ Bridge to Blockchain"  → 保留（主產品）
      "IBM MQ - IBM MQ Bridge to Blockchain component only"         → 排除（只有 Bridge）
      "IBM MQ - Explorer only"                                       → 保留（Explorer 屬正常元件）

    判斷規則：若產品行說 "except <keyword>"，則是主產品行，應保留；
    若說 "<keyword> only" 或 "<keyword> component"，才排除。
    """
    lower = product_line.lower()
    # 含 "except" 的行是主產品（排除掉某元件），應保留
    if "except" in lower:
        return False
    # 確認是否為專屬元件行（含關鍵字且沒有 "except"）
    return any(kw in lower for kw in EXCLUDED_PRODUCT_KEYWORDS)


def _parse_affected_versions(lines: List[str], aff_start: int, rem_start: int) -> str:
    """
    從 Affected Products and Versions 表格解析受影響的 MQ 版本範圍。

    IBM MQ Bulletin 表格文字結構（get_text 後）：
      Affected Products and Versions
      Affected Product(s)
      Version(s)
      IBM MQ                        ← 產品名行
      9.1.0.28 through 9.1.0.36    ← 版本範圍行（緊接產品名後）
      IBM MQ                        ← 下一個產品名
      9.2.0.0 through 9.2.0.42
      IBM MQ Bridge to Blockchain   ← 要過濾掉的產品
      9.4.0.0

    回傳格式（每個版本線一行，換行符分隔）：
      "9.1.0.28 – 9.1.0.36 LTS\n9.2.0.0 – 9.2.0.42 LTS\n..."
    """
    aff_end = rem_start if rem_start > aff_start else aff_start + 80
    aff_lines = lines[aff_start:aff_end]

    ranges: List[str] = []
    skip_next_version = False  # 上一行是需要跳過的產品，版本行也跳過

    i = 0
    while i < len(aff_lines):
        line = aff_lines[i].strip()
        i += 1

        if not line:
            continue

        # 偵測產品名行（包含 "IBM MQ" 且不是表頭）
        if re.match(r"IBM\s+MQ\b", line, re.IGNORECASE):
            skip_next_version = _is_excluded_product(line)
            continue

        # 若上一個產品需要跳過，也跳過此版本行
        if skip_next_version:
            skip_next_version = False
            continue

        # 嘗試解析版本範圍格式 "X.X.X.X to/through X.X.X.X [LTS|CD]"
        m = RE_VERSION_RANGE.search(line)
        if m:
            start_ver = m.group(1)
            end_ver = m.group(2)
            explicit_label = (m.group(3) or "").upper()   # 行尾顯式標記（LTS/CD）
            # 補全起始版本（若只有三碼如 9.3.0，補為 9.3.0.0）
            if start_ver.count(".") == 2:
                start_ver = start_ver + ".0"
            # 優先採用行尾顯式標記；否則依版本號第3碼判斷
            if explicit_label in ("LTS", "CD"):
                label = explicit_label
            elif _is_lts_version(end_ver):
                label = "LTS"
            elif _is_cd_version(end_ver):
                label = "CD"
            else:
                label = ""
            tag = f" {label}" if label else ""
            ranges.append(f"{start_ver} – {end_ver}{tag}")
            continue

        # 特殊格式：「9.4.0.0 LTS and CD」（單一版本但同時屬於 LTS 和 CD）
        m_lts_and_cd = re.match(
            r"(\d{1,2}\.\d+\.\d+\.\d+)\s+LTS\s+and\s+CD", line, re.IGNORECASE
        )
        if m_lts_and_cd:
            ver = m_lts_and_cd.group(1)
            ranges.append(f"{ver} LTS and CD")
            continue

        # 純版本號行（沒有 to/through）：可能是單一版本，行尾可帶 LTS/CD
        m_single = re.match(r"^(\d{1,2}\.\d+\.\d+\.\d+)(?:\s+(LTS|CD))?$", line, re.IGNORECASE)
        if m_single:
            ver = m_single.group(1)
            explicit = (m_single.group(2) or "").upper()
            if explicit in ("LTS", "CD"):
                label = explicit
            elif _is_lts_version(ver):
                label = "LTS"
            elif _is_cd_version(ver):
                label = "CD"
            else:
                label = ""
            tag = f" {label}" if label else ""
            ranges.append(f"{ver}{tag}")

    return "\n".join(ranges) if ranges else ""


def _fallback_find_affected_versions(text: str) -> str:
    """當找不到 Affected Products 區段時，從全文抓受影響版本（範圍格式）。"""
    ranges: List[str] = []
    seen: set = set()

    for m in RE_VERSION_RANGE.finditer(text):
        start_ver = m.group(1)
        end_ver = m.group(2)
        if start_ver.count(".") == 2:
            start_ver = start_ver + ".0"
        key = end_ver
        if key in seen:
            continue
        seen.add(key)
        if _is_lts_version(end_ver):
            label = "LTS"
        elif _is_cd_version(end_ver):
            label = "CD"
        else:
            label = ""
        tag = f" {label}" if label else ""
        ranges.append(f"{start_ver} – {end_ver}{tag}")

    return "\n".join(ranges) if ranges else ""


# ──────────────────────────────────────────────────────────────
# iFix URL 查找
# ──────────────────────────────────────────────────────────────

def _find_first_url_for_ifix(soup: BeautifulSoup, label: str) -> str:
    """從 soup 中找指定 iFix 編號的超連結。"""
    if not label:
        return ""
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = a.get_text(strip=True)
        if label.upper() in text.upper() or label.upper() in href.upper():
            return href
    return ""


# ──────────────────────────────────────────────────────────────
# Fix List 頁面爬取（Fixpack Release Date）
# ──────────────────────────────────────────────────────────────

# 快取：{ url → { version_str → date_str } }
_fix_list_cache: Dict[str, Dict[str, str]] = {}


def _fetch_fix_list_dates(driver, url: str) -> Dict[str, str]:
    """
    爬取 IBM MQ Fix List 頁面，回傳 { version_str → ga_date } 字典。

    Fix List 頁面表格格式（典型）：
      Version | Fix Pack | GA Date | ...
      9.1 LTS | 9.1.0.37 | 2026/06/24 | ...

    策略：找含 "9." 開頭版本號的儲存格，取同列的日期欄。
    """
    if url in _fix_list_cache:
        logger.debug("  Fix List 快取命中: %s", url)
        return _fix_list_cache[url]

    logger.info("  爬取 Fix List 頁面: %s", url)
    result: Dict[str, str] = {}

    try:
        driver.get(url)
        _wait_for_page_load(driver)
        soup = BeautifulSoup(driver.page_source, "lxml")

        # IBM MQ Fix List 頁面實際格式（2026-07 觀測）：
        # Table 0（第一個表格）為主要清單：
        #   欄 0: "IBM MQ 9.1.0.37"   ← 版本（帶 "IBM MQ " 前綴）
        #   欄 1: "Cumulative security update"
        #   欄 2: "24 Jun 2026"        ← Release Date（DD Mon YYYY）
        #   欄 3: 其他數字欄位
        month_map = {
            "jan": "01", "feb": "02", "mar": "03", "apr": "04",
            "may": "05", "jun": "06", "jul": "07", "aug": "08",
            "sep": "09", "oct": "10", "nov": "11", "dec": "12",
        }

        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all(["td", "th"])
                if len(cells) < 2:
                    continue

                # 欄 0：版本欄，格式 "IBM MQ X.Y.Z.W" 或 "X.Y.Z.W"
                cell0 = cells[0].get_text(" ", strip=True)
                ver_match = re.search(r"(\d{1,2}\.\d+\.\d+\.\d+)", cell0)
                if not ver_match:
                    continue
                ver = ver_match.group(1)

                # 在所有欄位中找日期
                date_str = ""
                for cell in cells:
                    cell_text = cell.get_text(" ", strip=True)

                    # 格式 DD Mon YYYY（例如 "24 Jun 2026"）
                    dm = re.search(
                        r"\b(\d{1,2})\s+"
                        r"(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
                        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
                        r"\s+(\d{4})\b",
                        cell_text, re.IGNORECASE
                    )
                    if dm:
                        mon = month_map.get(dm.group(2)[:3].lower(), "01")
                        date_str = f"{dm.group(3)}/{mon}/{int(dm.group(1)):02d}"
                        break

                    # 格式 YYYY/MM/DD 或 YYYY-MM-DD（備用）
                    dm2 = re.search(r"\b(\d{4}[/\-]\d{2}[/\-]\d{2})\b", cell_text)
                    if dm2:
                        date_str = dm2.group(1).replace("-", "/")
                        break

                    # 格式 Month DD, YYYY（例如 "June 24, 2026"）
                    dm3 = re.search(
                        r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
                        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
                        r"\s+(\d{1,2}),?\s+(\d{4})\b",
                        cell_text, re.IGNORECASE
                    )
                    if dm3:
                        mon = month_map.get(dm3.group(1)[:3].lower(), "01")
                        date_str = f"{dm3.group(3)}/{mon}/{int(dm3.group(2)):02d}"
                        break

                if date_str:
                    result[ver] = date_str
                    logger.debug("    Fix List: %s → %s", ver, date_str)

        if not result:
            logger.warning("  Fix List 頁面未解析到版本日期: %s", url)

    except Exception as e:
        logger.error("  爬取 Fix List 頁面失敗 (%s): %s", url, e)

    _fix_list_cache[url] = result
    return result


def _get_fixpack_date(driver, version: str) -> str:
    """
    根據 fixpack 版本號，從對應的 Fix List 頁面取得 Release Date。

    9.4 CD（第3碼≠0，例如 9.4.5.1）→ FIX_LIST_URLS["9.4_cd"]
    其他版本               → FIX_LIST_URLS[major_minor]
    """
    if not version:
        return ""
    mm = _major_minor(version)

    # 9.4 CD（第3碼≠0）→ 優先查 9.4_cd URL
    if mm == "9.4" and _is_cd_version(version):
        url = FIX_LIST_URLS.get("9.4_cd")
    else:
        url = FIX_LIST_URLS.get(mm)

    if not url:
        logger.debug("  無對應 Fix List URL: version=%s major_minor=%s", version, mm)
        return ""

    dates = _fetch_fix_list_dates(driver, url)
    date = dates.get(version, "")
    if date:
        logger.info("  Fixpack Release Date: %s → %s", version, date)
    else:
        logger.debug("  Fix List 找不到版本 %s 的日期", version)
    return date


# ──────────────────────────────────────────────────────────────
# Remediation 解析（多版本線 LTS / CD）
# ──────────────────────────────────────────────────────────────

def _parse_remediation(lines: List[str], rem_start: int) -> Dict:
    """
    從 Remediation 段落解析所有版本線的 iFix 編號與 Fixpack 版本。

    IBM MQ Remediation 段落有多個子段落，每個版本主幹各一組：
      For IBM MQ 9.1 LTS:
        · Apply IBM MQ 9.1.0.37
      For IBM MQ 9.2 LTS:
        · Apply IBM MQ 9.2.0.43
      For IBM MQ 9.3 LTS:
        · Apply IBM MQ 9.3.0.41
      For IBM MQ 9.3 CD, 9.4 LTS, 9.4 CD:
        · Apply IBM MQ 10

    回傳結果：
      fixpack_lts：多行字串，每行 "version"（LTS 版本列表）
      fixpack_cd ：多行字串，每行 "version"（CD 版本列表，含 MQ 10 說明）
      ifix_lts, ifix_cd：最先找到的 iFix 編號
    """
    result = {
        "ifix_lts": "", "ifix_lts_url": "",
        "ifix_cd": "", "ifix_cd_url": "",
        "fixpack_lts": "",   # 多行：每行一個 LTS fixpack 版本
        "fixpack_cd": "",    # 多行：每行一個 CD fixpack 版本（含 MQ 10 行）
        "fixpack_date_lts": "",  # 多行：每行對應 LTS fixpack 的 release date
        "fixpack_date_cd": "",   # 多行：每行對應 CD fixpack 的 release date
    }

    rem_lines = lines[rem_start:]

    # ── 找出所有版本子段落的起始行 ──
    # IBM MQ Bulletin 實際格式（2026-07 觀測）：
    #   "IBM MQ version 9.1 LTS"     ← 子段落標題（無前綴）
    #   "- IBM MQ version 9.1 LTS"   ← 子段落標題（帶 "- " 前綴，部分頁面）
    #   "Apply cumulative security update 9.1.0.37"  ← 版本行（可能被 IBM 網頁拆字）
    #   "IBM MQ version 9.3 CD, 9.4 LTS and 9.4 CD" ← 混合子段落
    #   "Upgrade to IBM MQ version 10"                ← MQ 10 升級行
    #   "Upgrade to IBM MQ version 9.4.5.1"           ← CD 具體版本升級行
    # 舊格式（保留相容）：
    #   "For IBM MQ 9.1 LTS:"
    section_starts: List[int] = []
    for i, l in enumerate(rem_lines):
        # 去掉可能的前導破折號/空白再比對
        stripped_l = re.sub(r"^[-–\s]+", "", l)
        if (re.match(r"IBM\s+MQ\s+version\b", stripped_l, re.IGNORECASE) or
                re.match(r"For IBM MQ\b", stripped_l, re.IGNORECASE)):
            section_starts.append(i)

    # ── 若無明確子段落，從全段落按版本號型態分類抓取 ──
    if not section_starts:
        lts_versions: List[str] = []
        cd_versions: List[str] = []
        lts_ifix = ""
        cd_ifix = ""

        for idx, line in enumerate(rem_lines[:100]):
            # 任何 Apply Fix Pack / Apply IBM MQ 行
            m = RE_APPLY_FP.search(line)
            if m:
                ver = m.group(1)
                if _is_lts_version(ver) and ver not in lts_versions:
                    lts_versions.append(ver)
                elif _is_cd_version(ver) and ver not in cd_versions:
                    cd_versions.append(ver)

            # iFix
            if re.search(r"interim.?fix", line, re.IGNORECASE):
                ifix = RE_IFIX.findall(line)
                if not ifix and idx + 1 < len(rem_lines):
                    nxt = RE_IFIX.fullmatch(rem_lines[idx + 1].strip().upper())
                    if nxt:
                        ifix = [rem_lines[idx + 1].strip().upper()]
                if ifix:
                    if RE_MQ_LTS_VERSION.search(line) and not lts_ifix:
                        lts_ifix = ifix[0].upper()
                    elif RE_MQ_CD_VERSION.search(line) and not cd_ifix:
                        cd_ifix = ifix[0].upper()
                    elif not lts_ifix:
                        lts_ifix = ifix[0].upper()
                    elif not cd_ifix:
                        cd_ifix = ifix[0].upper()

        result["fixpack_lts"] = "\n".join(lts_versions)
        result["fixpack_cd"] = "\n".join(cd_versions)
        result["ifix_lts"] = lts_ifix
        result["ifix_cd"] = cd_ifix
        return result

    # ── 逐一解析每個子段落 ──
    lts_versions: List[str] = []
    cd_versions: List[str] = []
    lts_ifix = ""
    cd_ifix = ""

    for sec_idx, sec_start in enumerate(section_starts):
        sec_end = section_starts[sec_idx + 1] if sec_idx + 1 < len(section_starts) else sec_start + 30
        sec_lines = rem_lines[sec_start:sec_end]
        sec_header = sec_lines[0] if sec_lines else ""
        sec_text = "\n".join(sec_lines)

        # 判斷此子段落屬於 LTS 還是 CD（由標題行判斷）
        # 標題範例：
        #   "For IBM MQ 9.1 LTS:"
        #   "For IBM MQ 9.3 CD, 9.4 LTS, 9.4 CD:"（混合，含 CD）
        #   "For IBM MQ:"（無版本分類）
        header_has_lts = bool(re.search(r"\bLTS\b|Long\s+Term\s+Support", sec_header, re.IGNORECASE))
        header_has_cd = bool(re.search(r"\bCD\b|Continuous\s+Delivery", sec_header, re.IGNORECASE))

        # 若標題未明確 LTS/CD，從段落內的版本號判斷
        if not header_has_lts and not header_has_cd:
            header_has_lts = bool(RE_MQ_LTS_VERSION.search(sec_text))
            header_has_cd = bool(RE_MQ_CD_VERSION.search(sec_text))

        # ── 把子段落所有行先合成一個乾淨文字，處理 IBM 網頁拆字問題 ──
        # IBM 網頁有時把 "cumulative" 拆成多個單字元行，合併後才能正確 Regex
        sec_joined = " ".join(sec_lines[1:])

        # 抓 Fixpack 版本
        for line in list(sec_lines[1:]) + [sec_joined]:
            # MQ 10 升級行（例如 "Upgrade to IBM MQ version 10"）
            if re.search(r"(?:Upgrade|Apply)\s+(?:to\s+)?IBM\s+MQ\s+(?:version\s+)?10\b", line, re.IGNORECASE):
                mq10_label = "MQ 10"
                if header_has_cd and mq10_label not in cd_versions:
                    cd_versions.append(mq10_label)
                elif mq10_label not in lts_versions and mq10_label not in cd_versions:
                    if header_has_lts:
                        lts_versions.append(mq10_label)
                    else:
                        cd_versions.append(mq10_label)
                continue

            # "Upgrade to IBM MQ version X.Y.Z.W"（CD 具體版本，例如 9.4.5.1）
            m_upgrade = re.search(
                r"(?:Upgrade|Apply)\s+(?:to\s+)?IBM\s+MQ\s+(?:version\s+)?(\d{1,2}\.\d+\.[1-9]\d*\.\d+)",
                line, re.IGNORECASE
            )
            if m_upgrade:
                ver = m_upgrade.group(1)
                if ver not in cd_versions:
                    cd_versions.append(ver)
                continue

            # 格式一：Apply cumulative security update X.Y.Z.W（含跨行合併文字）
            # 格式二：Apply Fix Pack X.Y.Z.W  /  Apply IBM MQ X.Y.Z.W
            m = RE_APPLY_FP.search(line)
            if not m:
                m = re.search(r"cumulative\s+security\s+update\s+(\d{1,2}\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
            if m:
                ver = m.group(1)
                # 優先由子段落標題（header_has_lts/cd）決定歸屬
                if header_has_lts and not header_has_cd:
                    if ver not in lts_versions:
                        lts_versions.append(ver)
                elif header_has_cd and not header_has_lts:
                    if ver not in cd_versions:
                        cd_versions.append(ver)
                else:
                    # 混合段落或無明確標記 → 由版本號第3碼決定
                    if _is_lts_version(ver) and ver not in lts_versions:
                        lts_versions.append(ver)
                    elif _is_cd_version(ver) and ver not in cd_versions:
                        cd_versions.append(ver)

        # 抓 iFix
        ifix = _extract_ifix(sec_lines)
        if ifix:
            if (header_has_lts or not header_has_cd) and not lts_ifix:
                lts_ifix = ifix
            elif header_has_cd and not cd_ifix:
                cd_ifix = ifix

    result["fixpack_lts"] = "\n".join(lts_versions)
    result["fixpack_cd"] = "\n".join(cd_versions)
    result["ifix_lts"] = lts_ifix
    result["ifix_cd"] = cd_ifix
    return result


def _extract_ifix(lines: List[str]) -> str:
    """從文字行列中抓取第一個 iFix 編號（支援同行與換行兩種格式）。"""
    for idx, line in enumerate(lines):
        if re.search(r"interim.?fix", line, re.IGNORECASE):
            ifix = RE_IFIX.findall(line)
            if ifix:
                return ifix[0].upper()
            if idx + 1 < len(lines):
                ifix_next = RE_IFIX.fullmatch(lines[idx + 1].strip().upper())
                if ifix_next:
                    return lines[idx + 1].strip().upper()
    return ""


# ──────────────────────────────────────────────────────────────
# 主解析函式
# ──────────────────────────────────────────────────────────────

def parse_bulletin_detail(driver, bulletin_dict: Dict) -> SecurityBulletin:
    """
    進入 Security Bulletin 內頁，解析：
      1. 每個 CVE 各自的 CVSS Base Score（存入 cve_details）
      2. Affected Products 段落：受影響 MQ 版本範圍（過濾 Bridge to Blockchain）
      3. Remediation 段落：iFix、各版本線 Fixpack 版本
      4. Fix List 頁面：各 Fixpack 版本的 Release Date

    回傳的 SecurityBulletin.cve_details 包含所有 CVE 的詳細資訊。
    主程式（scraper.py）負責將其展開為多筆輸出列。
    """
    url = bulletin_dict.get("url", "")
    title = bulletin_dict.get("title", "")
    cve_ids_from_list = bulletin_dict.get("cve_ids", [])
    list_severity = bulletin_dict.get("severity", "")
    publish_date = bulletin_dict.get("publish_date", "")

    logger.info("解析內頁: %s", url)

    bulletin = SecurityBulletin(
        title=title,
        bulletin_url=url,
        publish_date=publish_date,
        _list_severity=list_severity,
    )

    try:
        driver.get(url)
        _wait_for_page_load(driver)
        soup = BeautifulSoup(driver.page_source, "lxml")
        text = soup.get_text(separator="\n", strip=True)
        lines = [l.strip() for l in text.split("\n")]

        # 找各段落位置
        vd_start = next(
            (i for i, l in enumerate(lines) if "Vulnerability Details" in l), -1
        )
        aff_start = next(
            (i for i, l in enumerate(lines) if "Affected Products and Versions" in l), -1
        )
        rem_start = next(
            (i for i, l in enumerate(lines) if re.match(r"Remediation(?:/Fixes)?", l, re.IGNORECASE)), -1
        )

        if vd_start == -1:
            logger.warning("  找不到 Vulnerability Details 段落")
        if rem_start == -1:
            logger.warning("  找不到 Remediation 段落")

        vd_end = rem_start if rem_start > vd_start else len(lines)

        # 1. 解析每個 CVE 的 CVSS Score
        if vd_start != -1:
            bulletin.cve_details = _parse_cve_details(lines, vd_start, vd_end)
        elif cve_ids_from_list:
            bulletin.cve_details = _fallback_parse_cve_details(text, cve_ids_from_list)

        if bulletin.cve_details:
            logger.info(
                "  解析到 %d 個 CVE: %s",
                len(bulletin.cve_details),
                [(d.cve_id, d.cvss_score) for d in bulletin.cve_details]
            )

        if not bulletin.cve_details and cve_ids_from_list:
            for cid in cve_ids_from_list:
                bulletin.cve_details.append(CveDetail(cve_id=cid, cvss_score=0.0))
            logger.debug("  使用清單頁 CVE IDs 作為 fallback")

        # 2. 偵測 Bulletin 類型（lts / cd / both）
        if aff_start != -1 or rem_start != -1:
            bulletin_type = _detect_bulletin_type(
                lines,
                aff_start if aff_start != -1 else rem_start,
                rem_start
            )
        else:
            bulletin_type = _fallback_detect_bulletin_type(text, title)
        logger.info("  Bulletin 類型: %s", bulletin_type)

        # 3. 解析 Affected Versions（範圍格式，過濾 Bridge to Blockchain）
        if aff_start != -1:
            bulletin.affected_versions = _parse_affected_versions(lines, aff_start, rem_start)
        else:
            bulletin.affected_versions = _fallback_find_affected_versions(text)
        logger.info("  Affected Versions: %s", bulletin.affected_versions.replace('\n', ' | '))

        # 4. 解析 Remediation（多版本線 iFix + Fixpack）
        if rem_start != -1:
            fix_info = _parse_remediation(lines, rem_start)

            bulletin.ifix_lts = fix_info["ifix_lts"]
            bulletin.ifix_cd = fix_info["ifix_cd"]
            bulletin.fixpack_lts = fix_info["fixpack_lts"]
            bulletin.fixpack_cd = fix_info["fixpack_cd"]

            # 取 iFix URL
            bulletin.ifix_lts_url = _find_first_url_for_ifix(soup, bulletin.ifix_lts)
            bulletin.ifix_cd_url = _find_first_url_for_ifix(soup, bulletin.ifix_cd)

            logger.info("  LTS fixpacks: %s", bulletin.fixpack_lts.replace('\n', ', '))
            logger.info("  CD  fixpacks: %s", bulletin.fixpack_cd.replace('\n', ', '))

            # 5. 從 Fix List 頁面取各 Fixpack 的 Release Date
            lts_dates = []
            for ver in bulletin.fixpack_lts.split("\n"):
                ver = ver.strip()
                if ver and ver != "MQ 10":
                    d = _get_fixpack_date(driver, ver)
                    lts_dates.append(d)
                else:
                    lts_dates.append("")
            bulletin.fixpack_date_lts = "\n".join(lts_dates)

            cd_dates = []
            for ver in bulletin.fixpack_cd.split("\n"):
                ver = ver.strip()
                if ver and ver != "MQ 10":
                    d = _get_fixpack_date(driver, ver)
                    cd_dates.append(d)
                else:
                    cd_dates.append("")  # MQ 10 無固定 release date
            bulletin.fixpack_date_cd = "\n".join(cd_dates)

            logger.info("  LTS dates: %s", bulletin.fixpack_date_lts.replace('\n', ', '))
            logger.info("  CD  dates: %s", bulletin.fixpack_date_cd.replace('\n', ', '))

    except Exception as e:
        logger.error("解析內頁失敗 (%s): %s", url, e, exc_info=True)

    return bulletin


# ──────────────────────────────────────────────────────────────
# 展開多 CVE → 多筆輸出列
# ──────────────────────────────────────────────────────────────

def expand_bulletin_to_rows(bulletin: SecurityBulletin, min_cvss: float = 7.0) -> List[SecurityBulletin]:
    """
    將一個 SecurityBulletin（含多個 CVE）展開為多筆輸出列。
    每筆各對應一個 CVE，共用 Bulletin、iFix、Fixpack 等欄位。
    只保留 CVSS >= min_cvss 的 CVE（CVSS=0 且 list severity=High/Critical 的也保留）。
    """
    rows = []

    for detail in bulletin.cve_details:
        if detail.cvss_score >= min_cvss or (
            detail.cvss_score == 0.0
            and bulletin._list_severity.lower() in {"high", "critical"}
        ):
            if detail.cvss_score > 0:
                severity = detail.severity or _severity_from_score(detail.cvss_score)
            else:
                severity = bulletin._list_severity

            row = SecurityBulletin(
                title=bulletin.title,
                bulletin_url=bulletin.bulletin_url,
                affected_versions=bulletin.affected_versions,
                cve_id=detail.cve_id,
                severity=severity,
                publish_date=bulletin.publish_date,
                cvss_score=detail.cvss_score,
                ifix_lts=bulletin.ifix_lts,
                ifix_lts_url=bulletin.ifix_lts_url,
                ifix_cd=bulletin.ifix_cd,
                ifix_cd_url=bulletin.ifix_cd_url,
                fixpack_lts=bulletin.fixpack_lts,
                fixpack_date_lts=bulletin.fixpack_date_lts,
                fixpack_cd=bulletin.fixpack_cd,
                fixpack_date_cd=bulletin.fixpack_date_cd,
            )
            rows.append(row)

    if not rows and bulletin._list_severity.lower() in {"high", "critical"}:
        rows.append(SecurityBulletin(
            title=bulletin.title,
            bulletin_url=bulletin.bulletin_url,
            affected_versions=bulletin.affected_versions,
            cve_id="",
            severity=bulletin._list_severity,
            publish_date=bulletin.publish_date,
            cvss_score=0.0,
            ifix_lts=bulletin.ifix_lts,
            ifix_lts_url=bulletin.ifix_lts_url,
            ifix_cd=bulletin.ifix_cd,
            ifix_cd_url=bulletin.ifix_cd_url,
            fixpack_lts=bulletin.fixpack_lts,
            fixpack_date_lts=bulletin.fixpack_date_lts,
            fixpack_cd=bulletin.fixpack_cd,
            fixpack_date_cd=bulletin.fixpack_date_cd,
        ))

    return rows
