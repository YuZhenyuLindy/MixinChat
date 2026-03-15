# MixinChat - 密信聊天

端到端加密聊天工具，所有加密解密均在本地完成，不经过任何服务器。

## 在线使用

- [Vercel](https://yu-zhenyu-lindy-github-io.vercel.app/)
- [Cloudflare Workers](https://mixinchat.yuzhenyuyxl.workers.dev/encrypt/)
- [GitHub Pages](https://yuzhenyulindy.github.io/encrypt/encrypt-pwa.html)

## 功能

- AES-256-CBC + HMAC-SHA256 加密，PBKDF2 密钥派生（100,000 次迭代）
- 加密后自动复制，粘贴后自动解密
- 支持随机密钥生成，可保存密钥到本地
- 离线可用（PWA），可添加到手机主屏幕
- 微信小程序版本与网页版加密格式完全互通

## 使用方法

1. 双方约定一个共享密钥
2. 发送方：输入消息 → 点击"加密并复制" → 粘贴到微信发送
3. 接收方：复制加密消息 → 粘贴到解密框 → 自动解密

## 版本

| 版本 | 说明 |
|------|------|
| `index.html` | PWA 网页版，支持离线使用和添加到主屏幕 |
| `encrypt-pwa.html` | PWA 网页版 |
| `mixin-miniapp/` | 微信小程序版本 |

## 安全说明

- 加密算法：AES-256-CBC + HMAC-SHA256
- 密钥派生：PBKDF2-SHA256，100,000 次迭代
- 数据格式：`salt(16字节) + iv(16字节) + hmac(32字节) + 密文`
- 所有计算在本地完成，无网络请求，无数据上传
- 建议使用随机生成的16位密钥以获得最高安全性

