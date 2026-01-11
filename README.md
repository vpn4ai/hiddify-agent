**Hiddify Agent** is a lightweight, self-hosted agent written in Go, designed to work exclusively with a custom-modified Hiddify-Manager maintained by the author.
This agent is not a standalone tool. It acts as a node-side execution component for the custom Hiddify-Manager, responsible for executing commands, reporting status, and performing basic health checks.

**Hiddify Agent** 是一个使用 Go 编写的轻量级自托管 Agent，用于配合 定制版 Hiddify-Manager 实现节点侧的服务控制与基础自动化能力。
该 Agent 不是一个独立使用的通用工具，而是作为 Hiddify-Manager 的节点执行组件，用于执行指令、上报状态和进行基础健康检查。

**设计目标**
  简单、稳定、可控
  低资源占用，适合长期运行
  便于脚本化和系统集成
  避免引入复杂控制面板或重依赖组件
**使用前说明（重要）**
  ⚠️ 本项目必须结合作者维护的**定制版 Hiddify-Manager** 使用
  不适用于官方原版 Hiddify-Manager
  接口、配置格式与官方版本 不完全兼容
  单独运行没有实际意义
  如你不是在使用对应的定制版 Hiddify-Manager，请勿直接部署本 Agent。

**功能概览**
  Hiddify 服务的启动 / 停止 / 重启
  基础运行状态与健康检查
  轻量级本地 HTTP 接口（可选）
  作为 Manager → Node 的执行代理
**技术栈**
  语言：Go
  运行环境：Linux（推荐）
  定位：Agent / 后台守护进程 / 执行节点
