import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { JSX } from "typedoc";

const require = createRequire(import.meta.url);

const DOCUMENT_PAGES = {
  quickstart: "Quickstart.html",
  "issue-a-credential": "Issue_A_Credential.html",
  "persist-pending-issuance": "Persist_Pending_Issuance.html",
  "verify-a-credential": "Verify_A_Credential.html",
  "revoke-a-credential": "Revoke_A_Credential.html",
  "import-and-export-issuer-keys": "Import_And_Export_Issuer_Keys.html",
  "import-and-export-holder-keys": "Import_And_Export_Holder_Keys.html",
  "handle-thrown-javascript-errors": "Handle_Thrown_JavaScript_Errors.html",
  "choose-info-vs-blind-msg": "Choose_Info_Vs_Blind_Msg.html",
  "integrate-transport-outside-sdk": "Integrate_Transport_Outside_The_SDK.html",
  "integrate-transport-outside-the-sdk":
    "Integrate_Transport_Outside_The_SDK.html",
  architecture: "Architecture.html",
  "protocol-flow": "Protocol_Flow.html",
  "verification-and-revocation": "Verification_And_Revocation.html",
  "rust-api": "Rust_API.html",
};

const CORE_DOCUMENTS = [
  ["Quick Start", "Quickstart.html"],
  ["Architecture", "Architecture.html"],
  ["Protocol Flow", "Protocol_Flow.html"],
  ["Verification And Revocation", "Verification_And_Revocation.html"],
  ["Rust API", "Rust_API.html"],
];

const GUIDES = [
  ["Issue A Credential", "Issue_A_Credential.html"],
  ["Persist Pending Issuance", "Persist_Pending_Issuance.html"],
  ["Verify A Credential", "Verify_A_Credential.html"],
  ["Revoke A Credential", "Revoke_A_Credential.html"],
  ["Import And Export Issuer Keys", "Import_And_Export_Issuer_Keys.html"],
  ["Import And Export Holder Keys", "Import_And_Export_Holder_Keys.html"],
  ["Handle Thrown JavaScript Errors", "Handle_Thrown_JavaScript_Errors.html"],
  ["Choose Info Vs Blind Msg", "Choose_Info_Vs_Blind_Msg.html"],
  [
    "Integrate Transport Outside The SDK",
    "Integrate_Transport_Outside_The_SDK.html",
  ],
];

const PROJECT_DISPLAY_NAME = "PeerBadge SDK";
const NPM_MODULE_PAGE = "modules/pkg_peerbadge_wasm.html";
const NPM_MODULE_REFLECTION_NAME = "pkg/peerbadge_wasm";
const NPM_MODULE_DISPLAY_NAME = "PeerBadge SDK (npm)";
const RUST_PROTOCOL_PAGE = "rust/peerbadge_protocol/index.html";
const RUST_WASM_PAGE = "rust/peerbadge_wasm/index.html";

const PROJECT_OVERVIEW = `
<div class="docblock peerbadge-project-overview">
  <p>
    This is the PeerBadge SDK. The repository contains two Rust crates
    plus a generated npm package for browser and TypeScript applications.
  </p>
  <ul>
    <li>
      <a href="rust/peerbadge_protocol/index.html"><code>peerbadge-protocol</code></a>
      implements issuance, verification, canonicalization, and revocation for the
      <a href="https://peerbadge.org/">PeerBadge protocol</a>.
    </li>
    <li>
      <a href="rust/peerbadge_wasm/index.html"><code>peerbadge-wasm</code></a>
      exposes the <a href="https://peerbadge.org/">PeerBadge protocol</a> through wasm-bindgen.
    </li>
    <li>
      <a href="${NPM_MODULE_PAGE}"><code>${NPM_MODULE_DISPLAY_NAME}</code></a>
      is the generated npm package consumed by JavaScript and TypeScript apps.
    </li>
  </ul>
</div>`;

function fixDocumentSidebarLinks(html) {
  return html.replace(
    /href="(\.\.\/)?modules\.html#document\.([a-z-]+)"/g,
    (match, parentPrefix = "", documentSlug) => {
      const page = DOCUMENT_PAGES[documentSlug];

      if (!page) {
        return match;
      }

      return `href="${parentPrefix}documents/${page}"`;
    },
  );
}

function regexEscape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function relativeRoot(pageUrl) {
  return pageUrl.includes("/") ? "../" : "";
}

function sectionHeader(id, text) {
  return `<h2 id="${id}" class="section-header">${text}<a href="#${id}" class="anchor">\u00a7</a></h2>`;
}

function definitionList(items) {
  return `<dl class="item-table">${items
    .map(
      ({ className, href, title, text }) =>
        `<dt><a class="${className}" href="${href}" title="${title}">${text}</a></dt><dd></dd>`,
    )
    .join("")}</dl>`;
}

function sidebarBlock({ title, href, items }) {
  return `<h3><a href="${href}">${title}</a></h3><ul class="block">${items
    .map(
      ({ href: itemHref, text }) =>
        `<li class=""><a href="${itemHref}">${text}</a></li>`,
    )
    .join("")}</ul>`;
}

function sidebarDocumentItems(root) {
  return CORE_DOCUMENTS.map(([text, page]) => ({
    href: `${root}documents/${page}`,
    text,
  }));
}

function sidebarGuideItems(root) {
  return GUIDES.map(([text, page]) => ({
    href: `${root}documents/${page}`,
    text,
  }));
}

function sidebarModuleItems(root) {
  return [
    { href: `${root}${NPM_MODULE_PAGE}`, text: NPM_MODULE_DISPLAY_NAME },
    {
      href: `${root}${RUST_PROTOCOL_PAGE}`,
      text: "peerbadge-protocol (Rust)",
    },
    {
      href: `${root}${RUST_WASM_PAGE}`,
      text: "peerbadge-wasm (Rust)",
    },
  ];
}

function addProjectOverview(html) {
  if (html.includes("peerbadge-project-overview")) {
    return html;
  }

  return html.replace(
    '</rustdoc-toolbar></div><h2 id="section.modules"',
    `</rustdoc-toolbar></div>${PROJECT_OVERVIEW}<h2 id="section.modules"`,
  );
}

function relativeNpmModulePage(pageUrl) {
  return `${relativeRoot(pageUrl)}${NPM_MODULE_PAGE}`;
}

function linkProjectTitleToNpmModule(html, pageUrl) {
  const href = relativeNpmModulePage(pageUrl);
  const projectName = regexEscape(PROJECT_DISPLAY_NAME);

  return html
    .replace(
      new RegExp(
        `(<div class="sidebar-crate"><h2><a href=")[^"]+(">${projectName}</a>)`,
        "g",
      ),
      `$1${href}$2`,
    )
    .replace(
      new RegExp(
        `(<h2 class="location"><a href=")[^"]*(">${projectName}</a>)`,
        "g",
      ),
      `$1${href}$2`,
    );
}

function formatNpmModuleName(html) {
  return html
    .replaceAll(
      `>${NPM_MODULE_REFLECTION_NAME}<`,
      `>${NPM_MODULE_DISPLAY_NAME}<`,
    )
    .replaceAll(
      `title="${NPM_MODULE_REFLECTION_NAME}"`,
      `title="${NPM_MODULE_DISPLAY_NAME}"`,
    )
    .replaceAll(
      `<title>${NPM_MODULE_REFLECTION_NAME} -`,
      `<title>${NPM_MODULE_DISPLAY_NAME} -`,
    );
}

function hideNpmModuleDetails(html) {
  return html
    .replace(
      /<h3><a href="#section\.type-aliases">Type Aliases<\/a><\/h3><ul class="block">[\s\S]*?<\/ul>/g,
      "",
    )
    .replace(
      /<h3><a href="#section\.interfaces">Interfaces<\/a><\/h3><ul class="block">[\s\S]*?<\/ul>/g,
      "",
    )
    .replace(
      /<h2 id="section\.type-aliases" class="section-header">Type Aliases[\s\S]*?<\/dl>/g,
      "",
    )
    .replace(
      /<h2 id="section\.interfaces" class="section-header">Interfaces[\s\S]*?<\/dl>/g,
      "",
    );
}

function organizeMainSidebar(html, pageUrl) {
  const root = relativeRoot(pageUrl);
  const sidebarContent = [
    sidebarBlock({
      title: "Documents",
      href: `${root}modules.html#section.documents`,
      items: sidebarDocumentItems(root),
    }),
    sidebarBlock({
      title: "Modules",
      href: `${root}modules.html#section.modules`,
      items: sidebarModuleItems(root),
    }),
    sidebarBlock({
      title: "Guides",
      href: `${root}modules.html#section.guides`,
      items: sidebarGuideItems(root),
    }),
  ].join("");

  return html.replace(
    /(<nav class="sidebar"><div class="sidebar-crate">[\s\S]*?<\/div>)<div class="sidebar-elems">[\s\S]*?<\/div>/,
    `$1<div class="sidebar-elems">${sidebarContent}</div>`,
  );
}

function organizeProjectIndexSections(html) {
  const root = "";
  const documents = CORE_DOCUMENTS.map(([text, page]) => ({
    className: "foreigntype",
    href: `documents/${page}`,
    title: text,
    text,
  }));
  const modules = [
    {
      className: "mod",
      href: NPM_MODULE_PAGE,
      title: NPM_MODULE_DISPLAY_NAME,
      text: NPM_MODULE_DISPLAY_NAME,
    },
    {
      className: "mod",
      href: RUST_PROTOCOL_PAGE,
      title: "peerbadge-protocol (Rust)",
      text: "peerbadge-protocol (Rust)",
    },
    {
      className: "mod",
      href: RUST_WASM_PAGE,
      title: "peerbadge-wasm (Rust)",
      text: "peerbadge-wasm (Rust)",
    },
  ];
  const guides = GUIDES.map(([text, page]) => ({
    className: "foreigntype",
    href: `${root}documents/${page}`,
    title: text,
    text,
  }));

  const organizedSections = [
    sectionHeader("section.documents", "Documents"),
    definitionList(documents),
    sectionHeader("section.modules", "Modules"),
    definitionList(modules),
    sectionHeader("section.guides", "Guides"),
    definitionList(guides),
  ].join("");

  return html.replace(
    /<h2 id="section\.modules" class="section-header">Modules<a href="#section\.modules" class="anchor">§<\/a><\/h2><dl class="item-table">[\s\S]*?<\/dl><h2 id="section\.documents" class="section-header">Documents<a href="#section\.documents" class="anchor">§<\/a><\/h2><dl class="item-table">[\s\S]*?<\/dl>/,
    organizedSections,
  );
}

export function load(app) {
  app.renderer.on("beginRender", (event) => {
    const assetsDir = join(event.outputDirectory, "assets");
    mkdirSync(assetsDir, { recursive: true });
    copyFileSync(
      require.resolve("mermaid/dist/mermaid.min.js"),
      join(assetsDir, "mermaid.min.js"),
    );
  });

  app.renderer.on("endPage", (page) => {
    if (page.contents) {
      page.contents = fixDocumentSidebarLinks(page.contents);
      page.contents = linkProjectTitleToNpmModule(page.contents, page.url);
      page.contents = formatNpmModuleName(page.contents);
      page.contents = organizeMainSidebar(page.contents, page.url);

      if (page.url === "modules.html") {
        page.contents = addProjectOverview(page.contents);
      }

      if (page.url === "index.html" || page.url === "modules.html") {
        page.contents = organizeProjectIndexSections(page.contents);
      }

      if (page.url === NPM_MODULE_PAGE) {
        page.contents = hideNpmModuleDetails(page.contents);
      }
    }
  });

  app.renderer.hooks.on("body.end", (context) => {
    if (!context.options.getValue("customJs")) {
      return JSX.createElement(JSX.Fragment, null);
    }

    return JSX.createElement("script", {
      defer: true,
      src: context.relativeURL("assets/custom.js"),
    });
  });

  app.renderer.hooks.on("sidebar.end", (context) => {
    return JSX.createElement(
      "div",
      { class: "sidebar-elems" },
      JSX.createElement(
        "section",
        null,
        JSX.createElement("h3", null, "Links"),
        JSX.createElement(
          "ul",
          { class: "block" },
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              { href: "https://github.com/fedibtc/peerbadge-sdk" },
              "GitHub repo",
            ),
          ),
          JSX.createElement(
            "li",
            null,
            JSX.createElement(
              "a",
              {
                href: "https://www.npmjs.com/package/@fedibtc/peerbadge-sdk-wasm",
              },
              "npm package",
            ),
          ),
        ),
      ),
    );
  });
}
