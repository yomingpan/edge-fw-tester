# Edge Firewall Tester

本專案用於自動化測試多個目標主機/服務的網路可達性、防火牆狀態與應用層健康狀態。

## 環境建置

1. **建立 Python 虛擬環境**（建議 Python 3.8+）

```bash
python3 -m venv fw_tester
```

2. **啟動虛擬環境**

| 平台              | 啟動指令                                  |
|-------------------|-------------------------------------------|
| Linux/macOS       | `source fw_tester/bin/activate`           |
| Windows (cmd)     | `fw_tester\Scripts\activate`             |
| Windows (PowerShell) | `fw_tester\Scripts\Activate.ps1`      |

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

### 並行與依序測試

- 預設為依序測試（逐一執行，輸出順序與 flows 檔案一致）：
  ```bash
  python src/runner.py config/sample_flows.yml
  ```
- 啟用並行測試（大幅加速多目標檢查，結果順序不保證）：
  ```bash
  python src/runner.py config/sample_flows.yml --fast
  ```
- 強制依序測試（顯式指定）：
  ```bash
  python src/runner.py config/sample_flows.yml --no-fast
  ```

> 並行模式下，所有目標同時檢查，適合大量主機/服務；依序模式下，便於觀察逐步進度與除錯。

## 輸出說明

每一行格式如下：

```
OK     google-dns       8.8.8.8              UDP    53    OK
ERR    fail-demo        192.0.2.123          TCP    9999  ERR_HOST_UNREACHABLE
```
- 第一欄：簡短結果（OK/ERR）
- 最後一欄：詳細狀態說明

執行結束時，會額外輸出 summary 統計：

```
Summary: total=8  OK=5  ERR=3
```
- total：總測試數
- OK：成功數量
- ERR：失敗數量

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

## 進階功能

- 支援同一個 host 多個 port 測試：
  - flows 檔案可用 `port: 22, 80, 443` 逗號分隔多個 port
  - 會自動展開為多個測試，name 會自動加上 port 編號（如 github-ssh-22）
  - 範例：
    ```yaml
    - name: github-ssh
      host: github.com
      port: 22, 80, 443
      proto: tcp
    ```
