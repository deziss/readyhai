# qa-ui fixture: expected defects
Serve: `python3 -m http.server 8099 --directory tests/fixtures/qa-ui` then `readyhai qa http://127.0.0.1:8099/` (tag host nonprod for forms).

- index.html: console error on load; img missing.png 404; broken link missing-page.html (web.* findings from crawl).
- signup.html: qa.ui.validation_gap (email "not-an-email", etc.: no validation, GET to thanks.html returns 200). python http.server answers 501 to POST, hence the GET form.
- wide.html: qa.ui.responsive_overflow at 375 and 768.
- a11y.html: qa.ui.a11y (image-alt critical, label critical, color-contrast serious).
- v1/ vs v2/: qa.ui.visual_change. Run against /v1/, accept baseline, then serve /v2/ at the same URL (copy v2/index.html over v1/) -> diff > 0.5%.
