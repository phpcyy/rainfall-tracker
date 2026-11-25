# 降雨量监测看板

基于 GitHub Actions + GitHub Pages 的云端定时降雨量采集与加密展示项目。

- **采集频率**：北京时间每天 `08:00` 和 `20:00` 自动运行，双窗口去重汇总。
- **数据保护**：仓库内不保存任何明文数据，历史明细（`data/hourly.enc.json`）与看板数据（`docs/data.enc.json`）均使用 **PBKDF2-SHA256 + AES-256-GCM** 加密，访问页面需输入密码在浏览器本地解密查看。
