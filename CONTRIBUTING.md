# Contributing

Create a Markdown document in `_articles/` for English and add its Korean equivalent to `_ko_articles/`. Keep the same filename (slug) in both folders.

English front matter:
```yaml
---
title: "An English article title"
description: "One-sentence summary in English."
category: blue-team
tags: [Blue Team, Detection Engineering, DFIR]
level: Beginner
updated: "2026-10-17"
translation_url: /ko/wiki/article-slug/
---
```

Korean front matter:
```yaml
---
title: "한국어 문서 제목"
description: "한국어로 작성한 한 문장 소개."
category: blue-team
tags: [Blue Team, Detection Engineering, DFIR]
level: Beginner
updated: "2026-10-17"
translation_url: /wiki/article-slug/
---
```

Keep technical tags and category IDs consistent across languages. Categories are maintained in `_data/categories.yml` with `title`, `title_ko`, `desc`, and `desc_ko` values. UI strings live in `_data/i18n.json`. Use relative_url for links within the site.

Cite trustworthy public sources, note what is verified versus inferred, and never commit credentials, private organizational data, or copyrighted training materials without permission.
