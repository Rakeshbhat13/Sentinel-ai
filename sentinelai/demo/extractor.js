/**
 * SentinelAI — DOM Extractor (extractor.js)
 *
 * Run this in the browser (via Playwright's page.evaluate or a Chrome extension)
 * to collect DOM nodes with computed styles, bounding boxes, and text content.
 * The output is a JSON payload ready for POST /v1/scan.
 */
(function sentinelExtract() {
  const MAX_NODES = 500;
  const MIN_TEXT_LEN = 5;

  // ── Collect HTML comments ────────────────────────────────────────────────
  function collectComments() {
    const comments = [];
    const walker = document.createTreeWalker(
      document.documentElement, NodeFilter.SHOW_COMMENT, null
    );
    let node;
    while ((node = walker.nextNode())) {
      const text = (node.nodeValue || "").trim();
      if (text.length >= MIN_TEXT_LEN) comments.push(text);
    }
    return comments;
  }

  // ── Collect CSS pseudo-element content ───────────────────────────────────
  function collectPseudoContent() {
    const pseudos = [];
    const allEls = document.querySelectorAll("*");
    for (const el of allEls) {
      for (const pseudo of ["::before", "::after"]) {
        const content = window.getComputedStyle(el, pseudo).getPropertyValue("content");
        if (content && content !== "none" && content !== "normal" && content !== '""') {
          const text = content.replace(/^["']|["']$/g, "").trim();
          if (text.length >= MIN_TEXT_LEN) {
            pseudos.push({
              selector: cssSelector(el) + pseudo,
              content: text,
            });
          }
        }
      }
    }
    return pseudos;
  }

  // ── Build a unique CSS selector for an element ───────────────────────────
  function cssSelector(el) {
    if (el.id) return `#${el.id}`;
    const parts = [];
    while (el && el !== document.documentElement) {
      let selector = el.tagName.toLowerCase();
      if (el.className && typeof el.className === "string") {
        selector += "." + el.className.trim().split(/\s+/).join(".");
      }
      // Add nth-child for uniqueness
      if (el.parentElement) {
        const siblings = Array.from(el.parentElement.children).filter(
          (s) => s.tagName === el.tagName
        );
        if (siblings.length > 1) {
          const idx = siblings.indexOf(el) + 1;
          selector += `:nth-child(${idx})`;
        }
      }
      parts.unshift(selector);
      el = el.parentElement;
    }
    return parts.join(" > ");
  }

  // ── Collect DOM nodes with computed styles ───────────────────────────────
  function collectNodes() {
    const nodes = [];
    const walker = document.createTreeWalker(
      document.body, NodeFilter.SHOW_ELEMENT, null
    );
    let el;
    let count = 0;
    while ((el = walker.nextNode()) && count < MAX_NODES) {
      const tc = (el.textContent || "").trim();
      if (!tc || tc.length < MIN_TEXT_LEN) continue;
      // Skip containers with many children (focus on leaf-ish nodes)
      if (el.children.length > 10) continue;

      const cs = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();

      nodes.push({
        selector: cssSelector(el),
        tag: el.tagName.toLowerCase(),
        text_content: tc.slice(0, 2000),
        inner_text: (el.innerText || "").trim().slice(0, 2000),
        alt: el.getAttribute("alt") || "",
        title_attr: el.getAttribute("title") || "",
        computed_styles: {
          opacity: cs.opacity,
          font_size: cs.fontSize,
          color: cs.color,
          background_color: cs.backgroundColor,
          display: cs.display,
          visibility: cs.visibility,
          position: cs.position,
          left: cs.left,
          top: cs.top,
          width: cs.width,
          height: cs.height,
          clip: cs.clip,
          clip_path: cs.clipPath,
          z_index: cs.zIndex,
          overflow: cs.overflow,
          aria_hidden: el.getAttribute("aria-hidden") === "true",
        },
        bounding_box: {
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
        },
      });
      count++;
    }
    return nodes;
  }

  // ── Main ─────────────────────────────────────────────────────────────────
  const visibleText = (document.body.innerText || "").trim();
  return {
    url: window.location.href,
    visible_text: visibleText.slice(0, 50000),
    nodes: collectNodes(),
    html_comments: collectComments(),
    css_pseudo_content: collectPseudoContent(),
  };
})();
