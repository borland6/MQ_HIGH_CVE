# IBM Security Bulletin CVE Scraper — IBM MQ Agent 指南

> 此文件定義了 IBM MQ Security Bulletin CVE 爬蟲專案的
> **完整規格、架構、實作模式、IBM MQ 特有格式與注意事項**。
> 如需移植至其他 IBM 產品，請參考「產品適配」章節替換相關常數。

---

## 專案目標

開發一支 Python 程式，使用 **Selenium + ChromeDriver**，自動從 IBM Support 網站爬取
IBM MQ 的 Security Bulletin，篩選高風險 CVE（CVSS ≥ 7.0），
並輸出 **Bootstrap 5 + DataTables** 的 HTML 報表。

---

## 執行方式

```bash
pip install -r requirements.txt
python3 scraper.py                          # 預設：最近 30 天，CVSS >= 7.0
python3 scraper.py --days 90               # 最近 90 天
python3 scraper.py --days 90 --min-cvss 9.0 # 只取 Critical
python3 scraper.py --no-headless --verbose  # 顯示瀏覽器（除錯用，建議首次執行）
python3 scraper.py --output output/my.html  # 自訂輸出路徑
```

輸出報表預設檔名格式：`output/report-YYYY-MM-DD-HHMMss.html`

---

## 篩選條件（AND）

1. Severity 為 **High** 或 **Critical**（來自清單頁）
2. Publish Date 在 **N 天**內（`--days` 參數，預設 30）
3. CVSS Base Score **>= 7.0**（`--min-cvss` 參數，預設 7.0，來自內頁）

---

## 專案結構

```
mq-high-cve/
├── scraper.py          # 主程式：CLI 參數、主流程、WebDriver 初始化
├── crawler.py          # 清單頁爬蟲：爬取 IBM Security Bulletin 搜尋結果
├── bulletin_parser.py  # 內頁解析：CVSS、版本範圍、Fixpack、Fix List 日期爬取
├── report.py           # HTML 報表生成器
├── models.py           # 資料結構定義（dataclass）
├── requirements.txt    # 依賴套件
└── output/             # 輸出目錄
```

> ⚠️ **命名注意**：內頁解析模組**必須命名為 `bulletin_parser.py`**，不能命名為 `parser.py`。
> `parser` 是 Python 標準函式庫的內建模組，命名衝突會導致 `ModuleNotFoundError`。
> `scraper.py` 中以 `import bulletin_parser as detail_parser` 方式引入。

---

## requirements.txt

```
selenium
beautifulsoup4
lxml
python-dateutil
```

> **注意**：不使用 `webdriver-manager`，改用 Selenium 4.6+ 內建的 selenium-manager
> 自動下載 ChromeDriver。Chrome binary 需自行偵測路徑（見 scraper.py 說明）。

---

## IBM MQ 版本線規則（核心概念）

IBM MQ 版本號格式為 `主.次.修.微`，**第 3 碼（修訂號）決定版本線**：

| 版本線 | 規則 | 範例 |
|--------|------|------|
| **LTS**（Long Term Support）| 第 3 碼 = 0 | `9.1.0.34`、`9.3.0.41`、`9.4.0.25` |
| **CD**（Continuous Delivery）| 第 3 碼 ≠ 0 | `9.3.5.1`、`9.4.5.1` |

同一主幹版本（例如 9.3）可同時有 LTS（9.3.0.x）和 CD（9.3.1.x 至 9.3.5.x）兩條版本線。
目前有效版本主幹：**9.1、9.2、9.3、9.4**。

---

## 產品適配（移植至其他產品時必讀）

### 1. crawler.py — 搜尋 URL

```python
# IBM MQ（目前設定）
SEARCH_URL = "https://www.ibm.com/support/pages/bulletin/search/?q=IBM%20MQ"

# 其他產品範例
# WAS:     ?q=WebSphere%20Application%20Server
# IBM DB2: ?q=IBM%20Db2
```

### 2. bulletin_parser.py — 版本號 Regex

```python
# IBM MQ（支援多主幹 9.1~9.4、10.x）
RE_MQ_VERSION     = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")
RE_MQ_LTS_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.0\.\d+)\b")    # 第3碼=0
RE_MQ_CD_VERSION  = re.compile(r"\b(\d{1,2}\.\d+\.[1-9]\d*\.\d+)\b")  # 第3碼≠0
```

### 3. bulletin_parser.py — Bulletin 類型判斷

IBM MQ 沒有 WAS 的 Traditional/Liberty 分類，改為 LTS/CD 二分：
```python
# 偵測依據：Affected Products 表格與 Remediation 段落中出現的版本號
# lts:  只有 LTS 版本（第3碼=0）
# cd:   只有 CD 版本（第3碼≠0）
# both: 同時含有 LTS 與 CD
```

### 4. bulletin_parser.py — Remediation 解析關鍵字

IBM MQ Bulletin 實際頁面格式（2026-07 確認）：
```
# 子段落標題（兩種格式）：
"IBM MQ version 9.1 LTS"
"- IBM MQ version 9.1 LTS"   ← 部分頁面帶破折號前綴

# 版本行（兩種格式）：
"Apply cumulative security update 9.1.0.37"
"Apply cumulative security update 9.3.0.37"  ← 版本號可能被 HTML 拆字

# CD 升級行：
"Upgrade to IBM MQ version 9.4.5.1"
"Upgrade to IBM MQ version 10"
```

### 5. bulletin_parser.py — Affected Versions 格式

IBM MQ Bulletin 實際頁面格式：
```
"IBM MQ - all components except IBM MQ Bridge to Blockchain"  ← 保留（主產品）
"9.1.0.28 to 9.1.0.36 LTS"   ← 範圍格式（用 "to" 而非 "through"）
"IBM MQ - IBM MQ Bridge to Blockchain component only"         ← 過濾掉
"9.4.0.0 LTS and CD"          ← 特殊格式（單版本同時屬於 LTS/CD）
```

過濾關鍵字（`EXCLUDED_PRODUCT_KEYWORDS`）：
- `bridge to blockchain`
- `bridge for salesforce`
- `advanced message security`
- `managed file transfer`

### 6. bulletin_parser.py — Fix List URL 表

```python
FIX_LIST_URLS = {
    "9.1":    "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts",
    "9.2":    "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-92-lts",
    "9.3":    "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-93-lts",
    "9.4":    "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-94-lts",
    "9.4_cd": "https://www.ibm.com/support/pages/node/7157705",  # 9.4 CD 專用
}
```
9.4 CD 版本（第3碼≠0，例如 9.4.5.1）使用 `9.4_cd` URL，
9.4 LTS 版本（第3碼=0，例如 9.4.0.25）使用 `9.4` URL。

### 7. models.py — 欄位命名

```python
# IBM MQ 使用 LTS/CD 二組欄位（取代 WAS 的 V9/V8/Liberty 三組）
ifix_lts / ifix_lts_url
ifix_cd  / ifix_cd_url
fixpack_lts / fixpack_date_lts   # 多行字串，每行一個版本/日期
fixpack_cd  / fixpack_date_cd    # 多行字串，同上
```

`fixpack_lts` 和 `fixpack_cd` 為 `\n` 分隔的多行字串，每行一個版本號，
對應的 `fixpack_date_lts` / `fixpack_date_cd` 行數相同。

### 8. report.py — 報表標題與欄位標籤

```python
# 頁頭標題
"IBM MQ — High-Risk CVE Report"

# 表格欄 2 標題
"Affected MQ Version"

# Fixpack 版本標籤色彩
lts-tag：藍色 #cfe2ff
cd-tag ：綠色 #d1e7dd
```

---

## models.py — 資料結構

```python
from dataclasses import dataclass, field
from typing import List


@dataclass
class CveDetail:
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = ""   # Critical >= 9.0, High >= 7.0


@dataclass
class SecurityBulletin:
    # 欄位 1
    title: str = ""
    bulletin_url: str = ""
    # 欄位 2：受影響版本範圍（多行，每行一個版本線）
    affected_versions: str = ""
    # 欄位 3
    cve_id: str = ""
    # 欄位 4
    severity: str = ""
    # 欄位 5
    publish_date: str = ""
    # 欄位 6
    cvss_score: float = 0.0
    # 欄位 7：iFix
    ifix_lts: str = ""
    ifix_lts_url: str = ""
    ifix_cd: str = ""
    ifix_cd_url: str = ""
    # 欄位 8：Fixpack Version（多行字串，每行一個版本）
    fixpack_lts: str = ""   # 例如 "9.1.0.37\n9.2.0.43\n9.3.0.41"
    fixpack_cd: str = ""    # 例如 "9.4.5.1" 或 "MQ 10"
    # 欄位 9：Fixpack Release Date（多行字串，與 fixpack 行數對應）
    fixpack_date_lts: str = ""  # 例如 "2026/06/24\n2026/06/24\n2026/06/24"
    fixpack_date_cd: str = ""
    # 內部欄位
    _list_severity: str = ""
    cve_details: List[CveDetail] = field(default_factory=list)
```

---

## scraper.py — 主程式

### CLI 參數

| 參數 | 預設值 | 說明 |
|------|--------|------|
| `--days` | `30` | 爬取最近 N 天 |
| `--output` | `None`（自動產生含時間戳記的檔名） | 輸出路徑 |
| `--no-headless` | `False` | 顯示瀏覽器視窗 |
| `--min-cvss` | `7.0` | CVSS 篩選門檻 |
| `--verbose` / `-v` | `False` | Debug 詳細訊息 |

### Chrome Binary 自動偵測

實作 `_find_chrome_binary()` 依序搜尋：
1. 系統 PATH（`google-chrome`、`chromium` 等）
2. `~/.cache/selenium/chrome/linux64/*/chrome`（Selenium Manager 快取）
3. `~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome`（Playwright 快取）

用 `options.binary_location = chrome_binary` 設定後，直接 `webdriver.Chrome(options=options)` 即可。
建議設定 `driver.set_page_load_timeout(300)`，避免 IBM 頁面載入較慢時過早 timeout。

### 主流程

```
Step 1: crawler.fetch_bulletin_list(driver, days)
        → 回傳 list[dict]，每筆含 title, url, cve_ids, severity, publish_date

Step 2: for each item:
            bulletin = bulletin_parser.parse_bulletin_detail(driver, item)
            rows = bulletin_parser.expand_bulletin_to_rows(bulletin, min_cvss)

Step 3: 依 CVSS 分數降冪排序

Step 4: report.generate_html(rows, output_path, days, min_cvss)
```

每筆內頁解析之間加入 **1.5 秒延遲**，避免 rate limiting。

---

## crawler.py — 清單頁爬蟲

### 已知頁面結構（IBM Security Bulletin 搜尋頁通用）

- **Table ID**：`plc--results-table`（DataTable，已靜態嵌入 HTML，不需額外等待 AJAX）
- **Table 欄位（0-based）**：
  - `td[0]`：Security Bulletin 標題 + `href`（相對路徑，需加 `https://www.ibm.com`）
  - `td[1]`：Product（忽略）
  - `td[2]`：CVE ID（含 MITRE 連結）
  - `td[3]`：Severity（High / Critical / Medium / Low）
  - `td[4]`：Publish date（格式 `YYYY-MM-DD`）
- **同一篇 Bulletin 可能佔多列**（每個 CVE 一列），需以 URL 為 key 合併

### 每頁筆數設定

- 每頁顯示下拉是 **Select2 元件**（隱藏原生 `<select>`），class 為 `select2-hidden-accessible`
- 用 JavaScript 觸發：
  ```python
  driver.execute_script(
      "arguments[0].selectedIndex = arguments[1]; "
      "arguments[0].dispatchEvent(new Event('change'));",
      select_element, index_of_50
  )
  ```

### 下一頁按鈕

- CSS selector：`a.ibm-next-link`
- 用 `driver.execute_script("arguments[0].click();", btn)` 點擊
- 停止條件：本頁所有公告的最舊日期超出 `days` 天範圍

---

## bulletin_parser.py — 內頁解析

### 正規表示式常數

```python
RE_CVE            = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
RE_IFIX           = re.compile(r"\b((?:IT|PH|PI|PM|PK|PT|IF)\d{5,})\b", re.IGNORECASE)
RE_MQ_VERSION     = re.compile(r"\b(\d{1,2}\.\d+\.\d+\.\d+)\b")
RE_MQ_LTS_VERSION = re.compile(r"\b(\d{1,2}\.\d+\.0\.\d+)\b")
RE_MQ_CD_VERSION  = re.compile(r"\b(\d{1,2}\.\d+\.[1-9]\d*\.\d+)\b")
RE_VERSION_RANGE  = re.compile(
    r"(\d{1,2}\.\d+\.\d+(?:\.\d+)?)\s+(?:to|through)\s+(\d{1,2}\.\d+\.\d+\.\d+)"
    r"(?:\s+(LTS|CD))?", re.IGNORECASE
)
RE_APPLY_FP       = re.compile(r"(?:Apply\b.+?|Apply\s+IBM\s+MQ\s+)(\d{1,2}\.\d+\.\d+\.\d+)", re.IGNORECASE)
```

> ⚠️ IBM MQ 的 iFix 前綴為 **`IT`**（例如 `IT45123`），`PH/PI/PM` 為 WAS 格式，保留作 fallback。

### IBM MQ Bulletin 頁面文字結構

```
Vulnerability Details
CVEID:
CVE-2026-XXXX
CVSS Base score:
9.3             ← 緊接的非空行是分數
...

Affected Products and Versions
Affected Product(s)
Version(s)
IBM MQ - all components except IBM MQ Bridge to Blockchain  ← 保留
9.1.0.28 to 9.1.0.36 LTS   ← 範圍格式（注意是 "to" 而非 "through"）
IBM MQ - IBM MQ Bridge to Blockchain component only         ← 過濾
9.1.0.28 to 9.1.0.31 LTS
IBM MQ - Explorer only                                      ← 保留
9.4.0.0 LTS and CD          ← 特殊：同一版本同時屬於 LTS 和 CD

Remediation/Fixes
- IBM MQ version 9.1 LTS    ← 子段落標題（可能有 "- " 前綴）
Apply cumulative security update 9.1.0.37   ← 有時被 HTML 渲染拆字
- IBM MQ version 9.3 CD, 9.4 CD and IBM MQ Explorer 9.4.0.0
Upgrade to IBM MQ version 9.4.5.1           ← CD 具體版本
- IBM MQ version 9.3 CD, 9.4 LTS and 9.4 CD
Upgrade to IBM MQ version 10                ← MQ 10 升級
```

### CVSS Base Score 解析

- 找到 `"CVSS Base score:"` 標記行後，取**下一個非空行**的浮點數
- 一篇 Bulletin 含多個 CVE 時，每個 CVE 各自有獨立的 CVSS Score

### Affected Versions 解析（`_parse_affected_versions`）

1. 偵測產品名行（`IBM MQ\b`）→ 判斷是否為排除元件
   - 含 `"except"` 的行：**保留**（例如 "except IBM MQ Bridge to Blockchain"）
   - 含排除關鍵字且無 `"except"`：**過濾**（例如 "IBM MQ Bridge to Blockchain component only"）
2. 解析版本範圍行（`X to Y LTS/CD`）：格式 `起始 – 結尾 LTS/CD`
3. 特殊格式 `"9.4.0.0 LTS and CD"`：保留原始標記

### Remediation 解析（`_parse_remediation`）

1. 偵測子段落標題：去除前綴 `"- "` 後匹配 `"IBM MQ version\b"` 或 `"For IBM MQ\b"`
2. 把子段落各行合併（`sec_joined`）處理版本號拆字問題
3. 版本行優先順序：
   - `Upgrade/Apply to IBM MQ version 10` → CD: "MQ 10"
   - `Upgrade to IBM MQ version X.Y.Z.W`（第3碼≠0）→ CD
   - `Apply cumulative security update X.Y.Z.W` → 依子段落標題的 LTS/CD 分類
   - `Apply Fix Pack X.Y.Z.W` → 依第3碼決定 LTS/CD

### Fix List 日期爬取（`_fetch_fix_list_dates` + `_get_fixpack_date`）

Fix List 頁面格式（Table 0 第 0 欄為版本名）：
```
欄 0: "IBM MQ 9.1.0.37"   ← 版本（帶 "IBM MQ " 前綴，解析時去除）
欄 1: "Cumulative security update"
欄 2: "24 Jun 2026"        ← GA Date（DD Mon YYYY 格式）
```

- Fix List 頁面有快取（`_fix_list_cache`），同一 URL 在一次執行中只爬取一次
- 9.4 LTS（第3碼=0）→ `FIX_LIST_URLS["9.4"]`
- 9.4 CD（第3碼≠0）→ `FIX_LIST_URLS["9.4_cd"]`

### 多 CVE 展開（`expand_bulletin_to_rows`）

一篇 Bulletin 含多個 CVE → 展開為多筆輸出列：
- 共用：title, bulletin_url, affected_versions, publish_date, iFix, Fixpack 欄位
- 各自：cve_id, severity, cvss_score

只保留 `cvss_score >= min_cvss` 的 CVE（CVSS=0 且 severity=High/Critical 的也保留）。

---

## report.py — HTML 報表

### 表格欄位（9 欄，依序）

| # | 欄位名稱 | 內容說明 |
|---|---------|---------|
| 1 | Security Bulletin | 標題 + 原始頁面連結 |
| 2 | Affected MQ Version | 版本範圍字串（每行 `<br>` 分隔） |
| 3 | CVE-ID | 連結至 `https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}` |
| 4 | Severity | Critical（紅色）/ High（橙色）Bootstrap badge |
| 5 | Publish Date | 日期字串 |
| 6 | CVSS Base Score | 顏色標籤：≥9.0 紅色、7.0-8.9 橙色 |
| 7 | iFix | LTS/CD 各自連結（`LTS: ITXXXXX` / `CD: ITYYYYY`） |
| 8 | Fixpack Version | 多行：每行一個版本，LTS 藍色標籤、CD 綠色標籤 |
| 9 | Fixpack Release Date | 多行：與 Fixpack 行數一一對應的 GA 日期 |

### 技術規格

- Bootstrap 5 CDN：`https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css`
- DataTables CDN：`https://cdn.datatables.net/1.13.8/`（含 Bootstrap 5 整合版）
- 預設依 CVSS Score 降冪排序（欄位 index 5）
- 報表頂部統計卡片：Total / Critical / High / Days Range
- RWD 響應式設計，max-width 1400px
- DataTables 語言設定為繁體中文

### 顏色規則

| 項目 | 條件 | 顏色 |
|------|------|------|
| Severity badge | Critical | 紅色 `bg-danger` |
| Severity badge | High | 橙色 `#fd7e14` |
| CVSS badge | ≥ 9.0 | 紅色 |
| CVSS badge | 7.0–8.9 | 橙色 |
| Fixpack tag | LTS | 藍色 `#cfe2ff` |
| Fixpack tag | CD | 綠色 `#d1e7dd` |
| 列背景 | Critical 列 | 淺紅 `#fff5f5` |
| 列背景 | High 列 | 淺黃 `#fffbf0` |

---

## 重要注意事項

### 1. 模組命名衝突（必讀）
內頁解析模組**必須命名為 `bulletin_parser.py`**，不能命名為 `parser.py`。
`parser` 是 Python 內建模組，在某些 Python 版本下會造成 `ModuleNotFoundError`。

### 2. Chrome Binary 路徑
WSL / Linux 環境中 Chrome 可能在 Selenium 快取而非系統 PATH，
必須實作自動偵測邏輯，否則會出現 `cannot find Chrome binary` 錯誤。

### 3. Select2 下拉元件
每頁筆數的 `<select>` 是隱藏的（class `select2-hidden-accessible`），
必須用 JavaScript 設定 `selectedIndex` 並觸發 `change` event。

### 4. IBM MQ 頁面 "to" vs "through"
Affected Versions 表格版本範圍格式使用 **`to`**（例如 `9.1.0.28 to 9.1.0.36 LTS`），
**不是** `through`（WAS 頁面才用 `through`）。`RE_VERSION_RANGE` 需同時支援兩種。

### 5. Remediation 子段落標題帶破折號前綴
部分 IBM MQ Bulletin 的 Remediation 子段落標題格式為：
```
"- IBM MQ version 9.1 LTS"   ← 有 "- " 前綴
```
偵測前需先用 `re.sub(r"^[-–\s]+", "", l)` 去除前綴。

### 6. IBM 網頁版本號拆字問題
IBM 頁面有時將 "Apply cumulative security update 9.3.0.37" 渲染成多個單字元行：
```
'Apply'  'cumulat'  'i'  've security u'  ...  '9.3.0.37'
```
解法：把子段落各行合併為 `sec_joined = " ".join(sec_lines[1:])` 後再進行 Regex 解析。

### 7. "except" 產品行不應被過濾
IBM MQ Bulletin 產品行有兩種格式需區分：
```
"IBM MQ - all components except IBM MQ Bridge to Blockchain"  → 保留（主產品）
"IBM MQ - IBM MQ Bridge to Blockchain component only"         → 排除（元件專用）
```
判斷規則：含 `"except"` 的行視為主產品行，應**保留**。

### 8. Fix List URL 路由
9.4 版本依 LTS/CD 使用不同 Fix List URL：
- 9.4.0.x（第3碼=0，LTS）→ `fix-list-ibm-mq-version-94-lts`
- 9.4.1.x 以上（第3碼≠0，CD）→ `node/7157705`

### 9. Fix List 頁面日期格式
Fix List 頁面的 Release Date 欄格式為 **`DD Mon YYYY`**（例如 `24 Jun 2026`），
需用月份英文縮寫對照表轉換，不是 `YYYY/MM/DD` 格式。

### 10. 多 CVE 展開
一篇 Bulletin 若含 N 個 CVE，展開後每筆共用 Fixpack/iFix 欄位，
但 CVE-ID、CVSS Score、Severity 各不同。

---

## 各產品搜尋 URL 與適配提示

| 產品 | 搜尋 URL | Remediation 關鍵字 | 版本號格式 |
|------|----------|---------------------|-----------|
| **IBM MQ** | `?q=IBM%20MQ` | `IBM MQ version X.Y LTS/CD` | `9.x.0.x`（LTS）/ `9.x.y.x`（CD，y≠0） |
| WAS | `?q=WebSphere%20Application%20Server` | `For IBM WebSphere Application Server traditional:` | `9.x.x.x` / `8.x.x.x` |
| IBM DB2 | `?q=IBM%20Db2` | `For IBM Db2:` | `11.x.x.x` / `10.x.x.x` |
| IBM WebSphere Liberty | `?q=WebSphere+Liberty` | `Apply Liberty Fix Pack` | `YY.0.0.N` |

> ⚠️ 上述 Remediation 關鍵字與版本號格式**必須實際進入 IBM Security Bulletin 內頁確認**，
> 不同產品的段落標題可能不同，初次實作建議加 `--no-headless --verbose` 確認解析結果。

---

## IBM MQ 測試驗證用頁面

| IBM 節點 | 特殊狀況 |
|----------|---------|
| `node/7277749` | 多版本線（9.1/9.2/9.3 LTS + MQ 10 CD）；10 個 CVE；頁面格式正常 |
| `node/7271934` | 子段落標題帶 `"- "` 前綴；9.3 版本號被 HTML 拆字；CD = `9.4.5.1` |
| `node/7271933` | 9.1/9.2/9.3 LTS；LTS fixpack 三組 |
| `node/7277719` | 9.2/9.3/9.4 LTS + MQ 10 CD；含 9.4.0.25 LTS |
| `node/7271937` | 9.1/9.2/9.3/9.4 四組 LTS；有 9.4.0.21 LTS |

---

## 資料來源

- **IBM Security Bulletins 搜尋**：`https://www.ibm.com/support/pages/bulletin/search/`
- **CVE 詳細資訊**：`https://cve.mitre.org/`
- **IBM MQ Fix Lists**：
  - 9.1 LTS：`https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts`
  - 9.2 LTS：`https://www.ibm.com/support/pages/fix-list-ibm-mq-version-92-lts`
  - 9.3 LTS：`https://www.ibm.com/support/pages/fix-list-ibm-mq-version-93-lts`
  - 9.4 LTS：`https://www.ibm.com/support/pages/fix-list-ibm-mq-version-94-lts`
  - 9.4 CD：`https://www.ibm.com/support/pages/node/7157705`

---

*此文件基於 2026-07 IBM MQ CVE Scraper 專案實作所整理。
如 IBM 網站改版則相關 selector 可能需要重新確認。*
