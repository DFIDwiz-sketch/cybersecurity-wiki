# 글 작성 가이드

`_articles/` 디렉터리에 `example.md`처럼 Markdown 파일을 추가하세요. GitHub Pages가 글, 검색 색인, 태그 목록을 자동으로 갱신합니다.

```yaml
---
title: "문서 제목"
description: "짧고 구체적인 소개"
category: red-team
tags: [Red Team, Active Directory, Kerberos]
level: Beginner
updated: "2026-10-17"
---
## 개요
자유롭게 Markdown으로 작성합니다.
```

카테고리는 `_data/categories.yml`에서 관리합니다. 여러 태그를 사용할 수 있으며 일관된 철자와 대소문자를 권장합니다. 문서에는 참고자료와 확인 시점을 적고, 비밀번호·실제 내부 데이터·타인의 저작물을 허가 없이 공개하지 마세요.
