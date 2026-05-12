# KC110-EmbodiedAI 私有文档归档

这是一个纯静态的私有文档索引站，用于集中管理和打开 KC110-EmbodiedAI 相关的 HTML 文档。

当前首页的核心职责是展示文档日历和归档列表；文档数据从独立的 `files-data.js` 读取，具体内容文件放在 `content/` 目录下。

## 添加 HTML 文档

1. 在 `content/private` 下添加你的 HTML 文件，例如：

    ```text
    content/private/my-report.html
    ```

2. 如果文档不需要加密，也可以直接放在 `content/public` 下。

3. 运行构建脚本，将私有文档加密生成到 `content/public`，并更新 `files-data.js`：

    ```bash
    python build.py
    ```

4. git 提交到远程会自动更新网页。新增文档的提交统一采用 `content:` 前缀，例如:

    ```bash
    git add files-data.js
    git add content/public/my-report.html
    git commit -m "content: 添加我的报告"
    ```

## 文档组织结构

```text
├ KC110-EmbodiedAl / docs
├── README.md                         # 项目说明文档
├── index.html                        # 文档归档首页：左侧日历、本月文档列表、右侧全部文档列表
├── files-data.js                     # 文档索引数据源：由 build.py 根据 content/public 自动更新
├── build.py                          # 静态文档构建脚本：加密 private 并更新索引
├── content                           # 文档内容目录
│   ├── private                       # 本地明文私有文档目录，不提交
│   └── public                        # 加密后的公开文档目录
└── assets                            # 历史 PPT/演示模板相关资源；当前不是首页索引核心依赖，但可继续复用
    ├── css
    │   ├── main.css                  # 历史演示模板样式入口
    │   └── layers                    # 分层 CSS
    │       ├── 1-theme.css
    │       ├── 2-global.css
    │       ├── 3-layout.css
    │       ├── 4-utility.css
    │       └── 5-presentation-frame.css
    └── js
        ├── config.js                 # 历史演示模板配置
        └── core.js                   # 历史演示模板核心逻辑
```
