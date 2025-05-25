# Edge Firewall Tester

本專案用於自動化測試多個目標主機/服務的網路可達性、防火牆狀態與應用層健康狀態。

## 環境建置

1. **建立 Python 虛擬環境**（建議 Python 3.8+）

```bash
python3 -m venv fw_tester
```

2. **啟動虛擬環境**

- Linux/macOS:
  ```bash
  source fw_tester/bin/activate
  ```
- Windows (cmd):
  ```cmd
  fw_tester\Scripts\activate
  ```
- Windows (PowerShell):
  ```powershell
  fw_tester\Scripts\Activate.ps1
  ```

3. **安裝依賴套件**

```bash
pip install -r requirements.txt
```

> 若需進行封包監聽（sniffer），請以 root 權限執行，並安裝 scapy。

## 使用方法

### 基本測試

以 root 權限執行（建議使用 sudo -E 保留環境變數）：

```bash
sudo -E $(which python) -m src.runner config/sample_flows.yml
```

或測試另一組案例：

```bash
sudo -E $(which python) -m src.runner config/test_cases.yml
```

### 進階：自訂 timeout 與啟用 L7/sniff 檢查

可用 `--time-out` 參數自訂 L4 探測 timeout 秒數（預設 2.0 秒）：

```bash
sudo -E $(which python) -m src.runner config/sample_flows.yml --time-out 8
```

加上 `--full` 參數可啟用 L7 健康檢查與封包監聽：

```bash
sudo -E $(which python) -m src.runner config/sample_flows.yml --full
```

## 輸出說明

每一行格式如下：

```
OK     google-dns       8.8.8.8              UDP    53    OK
ERR    fail-demo        192.0.2.123          TCP    9999  ERR_HOST_UNREACHABLE
```
- 第一欄：簡短結果（OK/ERR）
- 最後一欄：詳細狀態說明

## 測試案例

- `config/sample_flows.yml`：常見公開服務與多種情境
- `config/test_cases.yml`：針對 OPEN/REFUSED/FILTERED/ERR_xxx 狀態的典型測試

---

如需自訂測試案例，請參考 `config/sample_flows.yml` 格式編輯。

## 單元測試（unittest/pytest）

本專案已內建 pytest 測試。

1. 啟動虛擬環境（如上）
2. 安裝 pytest：
   ```bash
   pip install pytest
   ```
3. 執行所有單元測試（一般情境）：
   ```bash
   pytest
   ```
   若測試內容涉及 sniffer 或需 root 權限，請用：
   ```bash
   sudo -E $(which pytest)
   ```

測試檔案位於 `tests/` 目錄下，包含 L4 探測與分類器等自動化測試。
