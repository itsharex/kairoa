<p align="center">
  <a href="https://github.com/covoyage/kairoa">
    <img width="200px" src="https://github.com/covoyage/kairoa/raw/main/src-tauri/icons/icon.png">
  </a>
</p>

<h1 align="center">
  💫 Kairoa ➟ 开发者工具箱 💫
</h1>

<p align="center">
    为开发者打造的现代跨平台桌面版开发工具。
</p>

<div align="left">

**简体中文 | [English](./README.md)**

</div>

<p align="center">
  <img src="screenshots/kairoa_zh.png" alt="主页" style="max-width: 100%; height: auto;" />
</p>

## 功能特性

### 🔐 Hash 计算器
- 计算文本和文件的哈希值
- 支持多种算法：MD5、SHA-1、SHA-256、SHA-384、SHA-512
- 支持拖拽文件
- 复制哈希值并显示视觉反馈

### ⏰ 时间转换器
- 时间戳和日期互转
- 支持时区选择（IANA 时区列表）
- 可搜索的时区下拉菜单
- 多种格式显示结果（YYYY-MM-DD HH:mm:ss 和 ISO 格式）
- 快速获取当前时间

### 🔑 UUID 生成器
- 生成单个或多个 UUID
- 可选择是否包含连字符
- 复制单个 UUID 或一键复制全部
- 可配置生成数量

### 📝 JSON 格式化器
- 格式化和压缩 JSON
- 格式化后的 JSON 语法高亮显示
- 实时验证
- 复制格式化后的 JSON 到剪贴板

### 🔧 编解码工具
- **Base64**: 文本和图片的编码/解码
- **URL**: URL 字符串的编码/解码
- **图片/Base64**: 图片与 Base64 格式互转
- 图片预览和下载支持
- 并排输入/输出布局

## 界面特性

- 🌓 **浅色/深色主题**: 支持浅色和深色模式切换
- 🌍 **国际化**: 支持英文和中文
- 🎨 **现代化 UI**: 使用 Tailwind CSS 构建
- 📱 **响应式设计**: 简洁直观的界面

## 技术栈

- **前端**: SvelteKit 5、TypeScript、Tailwind CSS
- **桌面端**: Tauri 2
- **图标**: Lucide Svelte
- **加密**: crypto-js

## 开发环境要求

- Node.js 18+ 和 npm
- Rust（最新稳定版）
- Tauri 的系统依赖：
  - **macOS**: Xcode Command Line Tools
  - **Linux**: 系统依赖（参见 [Tauri 文档](https://tauri.app/v1/guides/getting-started/prerequisites)）
  - **Windows**: Microsoft Visual Studio C++ Build Tools

## 安装

本项目使用 GitHub CI 构建所有平台的二进制文件。请前往 [Releases](https://github.com/covoyage/kairoa/releases) 页面下载对应平台的二进制文件。

### macOS

由于 macOS 二进制文件未使用 Apple Developer 证书进行代码签名，您可能需要先移除隔离属性才能运行应用：

```bash
xattr -r -c /Applications/kairoa.app
```

此命令会移除 macOS 为下载的应用添加的扩展属性，允许您在没有 Gatekeeper 警告的情况下运行应用。

## 开发

1. 克隆仓库：
```bash
git clone https://github.com/covoyage/kairoa.git
cd kairoa
```

2. 安装依赖：
```bash
npm install
```

3. 运行：
```bash
npm run tauri dev
```

## 贡献

欢迎贡献！请随时提交 Pull Request。

### 开发指南

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

### 代码规范

- 遵循 TypeScript 最佳实践
- 使用 Svelte 5 runes（`$state`、`$derived`、`$effect`）
- 遵循现有的代码风格和格式
- 为复杂逻辑添加注释

## 许可证

Apache License 2.0 - 详情请参阅 [LICENSE](LICENSE) 文件。

## 致谢

- 使用 [Tauri](https://tauri.app/) 构建
- UI 使用 [SvelteKit](https://kit.svelte.dev/) 构建
- 图标来自 [Lucide](https://lucide.dev/)
- 样式使用 [Tailwind CSS](https://tailwindcss.com/)

## 支持

如果您遇到任何问题或有疑问，请在 GitHub 上提交 issue。

---

使用 ❤️ 和 Tauri + SvelteKit 制作


