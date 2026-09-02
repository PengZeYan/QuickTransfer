# 苹方字体资产

项目所有用户界面统一使用自托管苹方字体。用户已确认拥有本项目所需授权；本文只记录项目内资产和校验值，不代替字体授权文件。向其他项目、客户或公开仓库分发前，仍应确认授权范围。

## 当前文件

| 字重映射 | 文件 | 字节数 | SHA-256 |
| --- | --- | ---: | --- |
| 100–599 | `public/assets/fonts/pingfang-sc-regular.woff2` | 5,196,812 | `5b0d7d92481aacd64fa81fdca90d9a7b421c235d8c0ba79023399d980851bc52` |
| 600–900 | `public/assets/fonts/pingfang-sc-bold.woff2` | 5,310,072 | `13b2c6ff12a9d5f436ae7ee1e64db36c32768c656082975a6f2d3c090555d20b` |

源码只保留上述两份 WOFF2。构建产物由 Vite 从 `public/` 复制，不再维护独立的旧维护页字体副本。

样式使用 `font-display: swap`，优先匹配本机苹方名称，随后加载自托管 WOFF2。新增页面、模态框和通知组件不得单独指定其他界面字体。

## 校验

```powershell
Get-FileHash .\public\assets\fonts\pingfang-sc-regular.woff2 -Algorithm SHA256
Get-FileHash .\public\assets\fonts\pingfang-sc-bold.woff2 -Algorithm SHA256
```

字体文件损坏、哈希变化或授权范围不明确时停止发布，不从不明来源重新下载替换。
