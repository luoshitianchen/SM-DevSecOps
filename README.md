# SM DevSecOps

安全研发平台：代码扫描、依赖审计、镜像扫描、SBOM 与流水线。

## 本地运行

```powershell
git clone https://github.com/luoshitianchen/SM-DevSecOps.git
cd SM-DevSecOps
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8340
```

访问：`http://127.0.0.1:8340/`

## 企业能力

- `/health` 健康探针
- `/readyz` 就绪探针
- `/api/overview` 业务概览
- `/api/items` 资源管理样例
- `/api/ops/metrics` 运维指标
- 安全响应头、CSP、TrustedHost
- Docker 只读文件系统、能力剥离、进程限制
- GitHub Actions CI 与安全扫描

## 质量门禁

```powershell
.\quality.ps1
```
