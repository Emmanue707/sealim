function jsQrLoaded() {
  return typeof globalThis.jsQR === "function";
}

function decodeWithJsQR(source) {
  const w =
    source.videoWidth || source.width || source.naturalWidth || source.displayWidth;
  const h =
    source.videoHeight || source.height || source.naturalHeight || source.displayHeight;
  if (!w || !h) {
    return null;
  }
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) {
    return null;
  }
  ctx.drawImage(source, 0, 0, w, h);
  const imageData = ctx.getImageData(0, 0, w, h);
  const result = globalThis.jsQR(imageData.data, w, h);
  const raw = result?.data;
  return raw ? raw.trim() : null;
}

export function canScanWithCamera() {
  return !!navigator.mediaDevices?.getUserMedia;
}

export function canDecodeQrImages() {
  return "BarcodeDetector" in window || jsQrLoaded();
}

export function qrDecoderUnavailableMessage() {
  if (canDecodeQrImages()) {
    return null;
  }
  return "QR image and camera decoding are unavailable in this browser. Paste the SL1: text instead.";
}

export async function scanQrInSource(source) {
  if ("BarcodeDetector" in window) {
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const codes = await detector.detect(source);
      const raw = codes[0]?.rawValue;
      if (raw) {
        return raw.trim();
      }
    } catch {
      /* try jsQR */
    }
  }
  if (jsQrLoaded()) {
    return decodeWithJsQR(source);
  }
  return null;
}

export async function decodeQrImage(file) {
  if (!canDecodeQrImages()) {
    throw new Error(
      "This browser cannot decode QR images locally. Paste the SL1: text instead.",
    );
  }
  const bitmap = await createImageBitmap(file);
  try {
    const text = await scanQrInSource(bitmap);
    if (text) {
      return text;
    }
    throw new Error("No QR code found in the image.");
  } finally {
    bitmap.close();
  }
}