# cattl3ya.github.io

Personal site for [www.johnmathot.com](https://www.johnmathot.com), built with [Hugo](https://gohugo.io/) and the [Risotto](https://github.com/joeroe/risotto) theme (git submodule in `themes/risotto`) and deployed to GitHub Pages by `.github/workflows/pages-deploy.yml`.

## Local development

```bash
git clone --recurse-submodules https://github.com/cattl3ya/cattl3ya.github.io.git
# or, in an existing clone: git submodule update --init
hugo server --baseURL http://localhost:1313/
```

Requires Hugo extended (the workflow pins 0.168.0).

## Layout

- `content/_index.md`: homepage text
- `content/about.md`: About page
- `content/posts/<slug>/index.md`: posts (images live next to each post)
- `hugo.toml`: site config
- `assets/css/custom.css`: style overrides
- `layouts/`: overrides of theme templates
- `static/`: files copied as-is (`CNAME`, favicons, avatar)
