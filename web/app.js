import init, { verify, registry_doc_id } from "./pkg/sealim_wasm.js";

const RESULT_COPY = {
  VALID: {
    title: "Valid",
    explain: "Signature, trust, and document hash all match.",
    glyph: "✓",
  },
  VALID_CLAIMS_ONLY: {
    title: "Valid (claims only)",
    explain: "Signature and trust check passed. No document file was supplied for hash comparison.",
    glyph: "✓",
  },
  STATUS_UNKNOWN: {
    title: "Registry status unknown",
    explain: "The payload expects a registry lookup but status could not be confirmed.",
    glyph: "?",
  },
  HASH_MISMATCH: {
    title: "Hash mismatch",
    explain: "The supplied file does not match the hash embedded in the QR payload.",
    glyph: "≠",
  },
  BAD_SIGNATURE: {
    title: "Bad signature",
    explain: "The payload signature does not verify under the issuer key from the trust file.",
    glyph: "×",
  },
  UNKNOWN_ISSUER: {
    title: "Unknown issuer",
    explain: "No matching key_id was found in the trust file.",
    glyph: "!",
  },
  KEY_NOT_VALID_AT_ISSUE: {
    title: "Key not valid at issue time",
    explain: "The issuer key was outside its validity window when the document was issued.",
    glyph: "!",
  },
  REVOKED: {
    title: "Revoked",
    explain: "The registry reports this document as revoked.",
    glyph: "×",
  },
  SUPERSEDED: {
    title: "Superseded",
    explain: "The registry reports this document as superseded.",
    glyph: "↺",
  },
  MALFORMED: {
    title: "Malformed QR text",
    explain: "The QR string could not be decoded as a Sealim payload.",
    glyph: "×",
  },
  UNSUPPORTED_VERSION: {
    title: "Unsupported version",
    explain: "The payload version is not supported by this verifier.",
    glyph: "×",
  },
};

const SHOW_DETAIL = new Set([
  "VALID",
  "VALID_CLAIMS_ONLY",
  "STATUS_UNKNOWN",
  "HASH_MISMATCH",
  "KEY_NOT_VALID_AT_ISSUE",
  "REVOKED",
  "SUPERSEDED",
]);

let trustJsonText = "";

async function loadWasm() {
  await init();
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

async function decodeQrImage(file) {
  if ("BarcodeDetector" in window) {
    const bitmap = await createImageBitmap(file);
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const codes = await detector.detect(bitmap);
    bitmap.close();
    const raw = codes[0]?.rawValue;
    if (raw) {
      return raw.trim();
    }
    throw new Error("No QR code found in the image.");
  }
  throw new Error(
    "This browser cannot decode QR images locally. Paste the SL1: text instead.",
  );
}

function registryBaseFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const v = params.get("registry");
  return v && v.trim() ? v.trim() : null;
}

async function fetchRegistryStatus(baseUrl, docIdHex) {
  const base = baseUrl.replace(/\/+$/, "");
  const url = `${base}/v1/documents/${docIdHex}`;
  try {
    const resp = await fetch(url, { method: "GET", cache: "no-store" });
    if (!resp.ok) {
      return "unreachable";
    }
    const data = await resp.json();
    const status = data?.status;
    if (status === "valid") return "valid";
    if (status === "revoked") return "revoked";
    if (status === "superseded") return "superseded";
    return "unreachable";
  } catch {
    return "unreachable";
  }
}

function clearResult() {
  const block = document.getElementById("result");
  block.hidden = true;
}

function renderResult(out) {
  const block = document.getElementById("result");
  const banner = document.getElementById("result-banner");
  const meta = document.getElementById("result-meta");
  const claimsTable = document.getElementById("claims-table");
  const claimsHeading = document.getElementById("claims-heading");
  const copy = RESULT_COPY[out.code] ?? {
    title: out.code,
    explain: "Verification finished.",
    glyph: "•",
  };

  block.hidden = false;
  block.className = `result code-${out.code.toLowerCase()}`;
  banner.innerHTML = "";
  const icon = document.createElement("span");
  icon.className = "result-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = copy.glyph;
  const textWrap = document.createElement("div");
  const title = document.createElement("p");
  title.className = "result-title";
  title.textContent = copy.title;
  const codeLine = document.createElement("p");
  codeLine.className = "result-code";
  codeLine.textContent = out.code;
  const explain = document.createElement("p");
  explain.className = "hint";
  explain.textContent = copy.explain;
  textWrap.append(title, codeLine, explain);
  banner.append(icon, textWrap);

  meta.innerHTML = "";
  if (out.issuer) {
    addMeta(meta, "Issuer", out.issuer);
  }
  if (out.doc_id) addMeta(meta, "doc_id", out.doc_id);
  if (out.key_id) addMeta(meta, "key_id", out.key_id);
  if (out.doc_hash) addMeta(meta, "doc_hash", out.doc_hash);
  if (out.issued_at != null) {
    const raw = String(out.issued_at);
    addMeta(meta, "issued_at", formatIssuedAtUtc(out.issued_at), raw);
  }
  if (out.detail) addMeta(meta, "detail", out.detail);

  const tbody = claimsTable.querySelector("tbody");
  tbody.innerHTML = "";
  const showClaims = SHOW_DETAIL.has(out.code) && out.claims?.length;
  claimsHeading.hidden = !showClaims;
  claimsTable.hidden = !showClaims;
  if (showClaims) {
    for (const row of out.claims) {
      const tr = document.createElement("tr");
      const th = document.createElement("th");
      th.scope = "row";
      th.textContent = row.key;
      const td = document.createElement("td");
      td.textContent = row.value;
      tr.append(th, td);
      tbody.appendChild(tr);
    }
  }
}

function formatIssuedAtUtc(secs) {
  const d = new Date(Number(secs) * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

function addMeta(dl, label, value, title) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  if (title) {
    dd.title = title;
  }
  dl.append(dt, dd);
}

async function resolveQrText() {
  const textarea = document.getElementById("qr-text");
  const fromText = textarea.value.trim();
  if (fromText) {
    return fromText;
  }
  const imageInput = document.getElementById("qr-image");
  const file = imageInput.files?.[0];
  if (file) {
    return decodeQrImage(file);
  }
  throw new Error("Enter QR text or choose a QR image.");
}

async function onVerify() {
  clearResult();
  const status = document.getElementById("trust-status");
  status.textContent = "";

  if (!trustJsonText) {
    status.textContent = "Load a trust file before verifying.";
    return;
  }

  let qrText;
  try {
    qrText = await resolveQrText();
  } catch (e) {
    status.textContent = e.message ?? String(e);
    return;
  }

  let fileBytes = null;
  const docInput = document.getElementById("doc-file");
  const docFile = docInput.files?.[0];
  if (docFile) {
    const buf = await readFileAsArrayBuffer(docFile);
    fileBytes = new Uint8Array(buf);
  }

  let registryStatus = null;
  const registryInput = document.getElementById("registry-url");
  const registryBase = (registryInput.value || "").trim() || registryBaseFromQuery();
  const docId = registry_doc_id(qrText);
  if (docId) {
    if (!registryBase) {
      registryStatus = "unreachable";
    } else {
      registryStatus = await fetchRegistryStatus(registryBase, docId);
    }
  }

  let out;
  try {
    out = verify(qrText, fileBytes, trustJsonText, registryStatus);
  } catch (e) {
    status.textContent = typeof e === "string" ? e : "Trust file could not be read.";
    return;
  }

  renderResult(out);
}

async function onTrustFile(file) {
  const status = document.getElementById("trust-status");
  if (!file) {
    trustJsonText = "";
    status.textContent = "";
    return;
  }
  try {
    trustJsonText = await readFileAsText(file);
    status.textContent = `Loaded ${file.name}`;
  } catch {
    trustJsonText = "";
    status.textContent = "Could not read the trust file.";
  }
}

function setDocumentFile(file) {
  const input = document.getElementById("doc-file");
  const name = document.getElementById("doc-name");
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  name.textContent = file
    ? `Selected ${file.name}. Hashing stays in this browser.`
    : "Drop a file here or choose one. Nothing is uploaded.";
}

async function loadDemo() {
  const status = document.getElementById("trust-status");
  clearResult();
  const base = new URL("../examples/university-of-waghi/", window.location.href);
  try {
    const [trustResp, qrResp, transcriptResp] = await Promise.all([
      fetch(new URL("trust.json", base)),
      fetch(new URL("qr.txt", base)),
      fetch(new URL("transcript.txt", base)),
    ]);
    if (!trustResp.ok || !qrResp.ok || !transcriptResp.ok) {
      status.textContent =
        "Demo fixtures are missing. Run examples/university-of-waghi/generate.sh from the repository.";
      return;
    }
    trustJsonText = await trustResp.text();
    document.getElementById("qr-text").value = (await qrResp.text()).trim();
    const transcriptBytes = await transcriptResp.arrayBuffer();
    setDocumentFile(
      new File([transcriptBytes], "transcript.txt", { type: "text/plain" }),
    );
    status.textContent =
      "Loaded University of Waghi demo trust, QR text, and transcript.";
    await onVerify();
  } catch {
    status.textContent =
      "Could not load demo files. Serve the repository root (see README) and open /web/.";
  }
}

function setupCamera() {
  const btn = document.getElementById("scan-camera");
  const video = document.getElementById("camera-preview");
  if (!("BarcodeDetector" in window) || !navigator.mediaDevices?.getUserMedia) {
    return;
  }
  btn.hidden = false;
  let stream;
  let timer;

  btn.addEventListener("click", async () => {
    if (stream) {
      stop();
      return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
      });
      video.srcObject = stream;
      video.hidden = false;
      await video.play();
      btn.textContent = "Stop camera";
      timer = window.setInterval(async () => {
        try {
          const detector = new BarcodeDetector({ formats: ["qr_code"] });
          const codes = await detector.detect(video);
          const raw = codes[0]?.rawValue;
          if (raw) {
            document.getElementById("qr-text").value = raw.trim();
            stop();
          }
        } catch {
          /* ignore frame errors */
        }
      }, 500);
    } catch {
      document.getElementById("trust-status").textContent =
        "Camera access was denied or is unavailable.";
    }
  });

  function stop() {
    if (timer) window.clearInterval(timer);
    timer = undefined;
    if (stream) {
      for (const t of stream.getTracks()) t.stop();
      stream = undefined;
    }
    video.hidden = true;
    video.srcObject = null;
    btn.textContent = "Scan with camera";
  }
}


function setupDocDrop() {
  const zone = document.getElementById("doc-drop");
  const input = document.getElementById("doc-file");
  const name = document.getElementById("doc-name");
  if (!zone || !input || !name) {
    return;
  }

  function showName(file) {
    name.textContent = file
      ? `Selected ${file.name}. Hashing stays in this browser.`
      : "Drop a file here or choose one. Nothing is uploaded.";
  }

  input.addEventListener("change", () => showName(input.files?.[0]));

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  });
  zone.addEventListener("dragleave", (e) => {
    if (!zone.contains(e.relatedTarget)) {
      zone.classList.remove("dragover");
    }
  });
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    const file = e.dataTransfer?.files?.[0];
    if (!file) {
      return;
    }
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    showName(file);
  });

  document.addEventListener("dragover", (e) => e.preventDefault());
  document.addEventListener("drop", (e) => e.preventDefault());
}

function wireUi() {
  document.getElementById("verify-btn").addEventListener("click", () => {
    onVerify().catch((e) => {
      document.getElementById("trust-status").textContent = String(e);
    });
  });
  document.getElementById("trust-file").addEventListener("change", (ev) => {
    onTrustFile(ev.target.files?.[0]).catch(() => {});
  });
  document.getElementById("demo-trust").addEventListener("click", () => {
    loadDemo().catch(() => {});
  });
  const reg = registryBaseFromQuery();
  if (reg) {
    document.getElementById("registry-url").value = reg;
  }
  setupCamera();
  setupDocDrop();
}

await loadWasm();
wireUi();