# Cybersecurity Wiki

An open, bilingual cybersecurity knowledge base built with **GitHub Pages and Jekyll**.

- English (default): https://dfidwiz-sketch.github.io/cybersecurity-wiki/
- Korean: https://dfidwiz-sketch.github.io/cybersecurity-wiki/ko/

## Features

- Full-text document search and Ctrl/Cmd + K quick search
- Multiple tag and category filters
- English / 한국어 switch, including corresponding article pages
- Separate search indexes for each language
- Dark and light themes, mobile navigation, article table of contents
- Markdown authoring without a database or paid search service

## Publishing

In **Settings → Pages**, select **Deploy from a branch**, `main`, `/(root)`, and save. GitHub Pages will build Jekyll pages automatically.

## Authoring translations

Each document is a pair with the same file name:
- English: `_articles/<slug>.md` → `/wiki/<slug>/`
- Korean: `_ko_articles/<slug>.md` → `/ko/wiki/<slug>/`

Both versions declare `translation_url` pointing to the paired path. Use the same canonical category IDs and tag strings in both languages to preserve tag filters when switching languages.

The home, search, and tag pages are translated under the `ko/` folder. Interface translations are in `_data/i18n.json` and category names in `_data/categories.yml`. See [CONTRIBUTING.md](CONTRIBUTING.md).

All site pages use separate language-specific URLs; the language switch preserves relevant query parameters.
