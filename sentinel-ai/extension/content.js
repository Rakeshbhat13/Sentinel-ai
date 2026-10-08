// SentinelAI — Invisible DOM Sniffer & Visibility Delta Extractor
// Ponytail: Zero dependencies. Native browser APIs only.

const BACKEND = "http://127.0.0.1:8000";

// ── Detection Heuristics ─────────────────────────────────────────────────────

function isHiddenByStyle(el) {
  const cs = window.getComputedStyle(el);
  if (cs.display === "none") return "display:none";
  if (cs.visibility === "hidden") return "visibility:hidden";
  if (parseFloat(cs.opacity) === 0) return "opacity:0";
  if (parseFloat(cs.fontSize) === 0) return "font-size:0";
  // Off-screen placement (common trick: position:absolute; left:-9999px)
  if (parseInt(cs.left, 10) < -5000 || parseInt(cs.top, 10) < -5000) return "off-screen";
  return null;
}

function isZeroPixelBox(el) {
  const rect = el.getBoundingClientRect();
  return rect.width === 0 || rect.height === 0;
}

function isColorCamouflaged(el) {
  const cs = window.getComputedStyle(el);
  const color = cs.color;
  const bg = cs.backgroundColor;
  // Only flag if both are explicit and identical (skip transparent backgrounds)
  if (bg && bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent" && color === bg) {
    return "color-camouflage";
  }
  return null;
}

// ── DOM Traversal ────────────────────────────────────────────────────────────

function extractSuspiciousNodes() {
  const suspicious = [];
  // Walk all elements that can contain text
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, null);

  let node;
  while ((node = walker.nextNode())) {
    const textContent = (node.textContent || "").trim();
    const innerText = (node.innerText || "").trim();

    // Skip empty nodes
    if (!textContent) continue;
    // Skip nodes with lots of children (containers) — focus on leaf-ish nodes
    if (node.children.length > 5) continue;

    // ── Visibility Delta: textContent has text the human can't see ──
    const delta = textContent.length - innerText.length;
    if (delta <= 0) continue; // No hidden content

    // Determine the hiding technique
    const hiddenText = textContent.replace(innerText, "").trim();
    if (!hiddenText || hiddenText.length < 10) continue; // Ignore tiny fragments

    const technique =
      isHiddenByStyle(node) ||
      (isZeroPixelBox(node) ? "zero-pixel-box" : null) ||
      isColorCamouflaged(node) ||
      (delta > innerText.length * 2 ? "visibility-delta" : null);

    if (technique) {
      suspicious.push({
        tag: node.tagName.toLowerCase(),
        technique,
        hiddenText: hiddenText.slice(0, 1000), // Cap payload size
        visibleText: innerText.slice(0, 200),
        xpath: getXPath(node),
      });
    }
  }
  return suspicious;
}

function getXPath(el) {
  const parts = [];
  while (el && el.nodeType === Node.ELEMENT_NODE) {
    let idx = 1;
    for (let sib = el.previousElementSibling; sib; sib = sib.previousElementSibling) {
      if (sib.tagName === el.tagName) idx++;
    }
    parts.unshift(`${el.tagName.toLowerCase()}[${idx}]`);
    el = el.parentElement;
  }
  return "/" + parts.join("/");
}

// ── Reporting ────────────────────────────────────────────────────────────────

async function reportToBackend(findings) {
  if (!findings.length) return;

  const payload = {
    url: window.location.href,
    timestamp: new Date().toISOString(),
    findings,
  };

  try {
    const res = await fetch(`${BACKEND}/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const verdict = await res.json();

    if (verdict.action === "block" || verdict.action === "sanitize") {
      // Strip the malicious nodes from the DOM so agents can't read them
      for (const f of findings) {
        const result = document.evaluate(
          f.xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
        );
        if (result.singleNodeValue) {
          result.singleNodeValue.textContent = result.singleNodeValue.innerText || "";
          console.warn(`[SentinelAI] Sanitized hidden payload at ${f.xpath}`);
        }
      }
    }
    console.log("[SentinelAI] Verdict:", verdict);
  } catch (err) {
    console.error("[SentinelAI] Backend unreachable:", err.message);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

(function run() {
  const findings = extractSuspiciousNodes();
  if (findings.length) {
    console.warn(`[SentinelAI] Detected ${findings.length} suspicious hidden element(s).`);
    reportToBackend(findings);
  } else {
    console.log("[SentinelAI] Page clean.");
  }
})();
