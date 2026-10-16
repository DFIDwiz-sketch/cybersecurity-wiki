# Cybersecurity Wiki

검색과 다중 태그 탐색을 지원하는 현대적인 한국어 사이버보안 위키입니다. 기존 `dfir-guide`와는 별개입니다.

**사이트:** https://dfidwiz-sketch.github.io/cybersecurity-wiki/

## GitHub Pages 활성화

1. 저장소 **Settings → Pages**.
2. **Build and deployment → Source: Deploy from a branch**.
3. **Branch: main / Folder: /(root)**로 저장.
4. Jekyll 빌드가 완료되면 위 주소로 접속하세요.

## 제공 기능
- Ctrl+K / ⌘K 빠른 검색, 본문을 포함한 통합 검색
- 태그 클릭으로 관련 문서 전체 보기, 카테고리 + 다중 태그 필터
- 모바일 메뉴, 다크·라이트 모드, 문서 목차, 수정 제안
- Markdown 문서 추가 시 자동 검색 색인 생성

## 콘텐츠 작성
`_articles/`에 새 Markdown 파일을 추가하세요. 형식은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참조합니다. 태그/카테고리는 `_data/categories.yml`의 분류와 자유로운 태그 조합을 사용합니다.

## 기술
GitHub Pages 기본 Jekyll 빌드 + 순수 HTML/CSS/JavaScript. 외부 검색 서비스나 유료 데이터베이스가 필요 없습니다.

오류나 수정사항은 GitHub Issue 또는 Pull Request로 공유해 주세요.
