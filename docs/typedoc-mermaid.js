(function () {
  const MERMAID_SELECTOR = "pre > code.mermaid";

  function installStyles() {
    if (document.getElementById("peerbadge-mermaid-style")) {
      return;
    }

    const style = document.createElement("style");
    style.id = "peerbadge-mermaid-style";
    style.textContent = `
      .mermaid-diagram {
        margin: 1rem 0 1.25rem;
        overflow-x: auto;
      }

      .mermaid-diagram svg {
        max-width: 100%;
        height: auto;
      }

      .mermaid-error {
        color: var(--code-attribute-color, #f66);
      }
    `;
    document.head.appendChild(style);
  }

  function readCodeBlock(node) {
    let text = "";

    for (const child of node.childNodes) {
      if (child.nodeName === "BR") {
        text += "\n";
      } else if (child.nodeType === Node.TEXT_NODE) {
        text += child.textContent;
      } else {
        text += readCodeBlock(child);
      }
    }

    return text;
  }

  function prepareDiagrams() {
    return Array.from(document.querySelectorAll(MERMAID_SELECTOR)).map(
      (codeBlock) => {
        const source = readCodeBlock(codeBlock).trim();
        const diagram = document.createElement("div");
        diagram.className = "mermaid mermaid-diagram";
        diagram.textContent = source;
        codeBlock.parentElement.replaceWith(diagram);
        return diagram;
      },
    );
  }

  function loadMermaid() {
    if (window.mermaid) {
      return Promise.resolve(window.mermaid);
    }

    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = `${document.documentElement.dataset.base || "./"}assets/mermaid.min.js`;
      script.onload = () => resolve(window.mermaid);
      script.onerror = () => reject(new Error("Failed to load Mermaid"));
      document.head.appendChild(script);
    });
  }

  function preferredTheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "default";
  }

  async function renderMermaid() {
    const diagrams = prepareDiagrams();

    if (diagrams.length === 0) {
      return;
    }

    installStyles();

    try {
      const mermaid = await loadMermaid();
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: preferredTheme(),
      });
      await mermaid.run({ nodes: diagrams });
    } catch (error) {
      for (const diagram of diagrams) {
        diagram.classList.add("mermaid-error");
      }
      console.error(error);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderMermaid, {
      once: true,
    });
  } else {
    renderMermaid();
  }
})();
