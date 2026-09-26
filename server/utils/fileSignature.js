const path = require("path");

/**
 * Server-side file type detection based on magic bytes (file signatures).
 * Used to validate uploads against their ACTUAL content instead of trusting
 * the browser-supplied Content-Type / file extension (CWE-434, CWE-345).
 */

const startsWith = (buf, bytes, offset = 0) =>
  buf.length >= offset + bytes.length &&
  bytes.every((b, i) => buf[offset + i] === b);

const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

const SIGNATURES = [
  { mime: "application/pdf", test: (b) => startsWith(b, ascii("%PDF-")) },
  { mime: "image/jpeg", test: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  {
    mime: "image/png",
    test: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  },
  {
    mime: "image/webp",
    test: (b) => startsWith(b, ascii("RIFF")) && startsWith(b, ascii("WEBP"), 8),
  },
  {
    mime: "image/gif",
    test: (b) => startsWith(b, ascii("GIF87a")) || startsWith(b, ascii("GIF89a")),
  },
  {
    mime: "application/msword",
    test: (b) => startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
  },
  {
    // DOCX is a ZIP container; require a Word part so arbitrary ZIPs are rejected
    mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    test: (b) => startsWith(b, [0x50, 0x4b, 0x03, 0x04]) && b.includes("word/"),
  },
];

const EXTENSIONS = {
  "application/pdf": [".pdf"],
  "image/jpeg": [".jpg", ".jpeg"],
  "image/png": [".png"],
  "image/webp": [".webp"],
  "image/gif": [".gif"],
  "application/msword": [".doc"],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
};

const normalizeMime = (mime = "") => {
  const m = String(mime).toLowerCase().trim();
  return m === "image/jpg" ? "image/jpeg" : m;
};

/** Returns the detected MIME type from the buffer's magic bytes, or null. */
const detectMime = (buffer) => {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return null;
  const match = SIGNATURES.find((s) => s.test(buffer));
  return match ? match.mime : null;
};

class FileValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "FileValidationError";
    this.status = 400;
  }
}

/**
 * Validate an uploaded file's real content against an allow-list.
 * The detected type must be allowed, match the declared MIME type and
 * (when a filename is given) match the file extension.
 *
 * @param {{ buffer: Buffer, mimetype?: string, originalname?: string }} file
 * @param {string[]} allowedMimes
 * @returns {string} detected MIME type
 */
const validateFile = ({ buffer, mimetype, originalname } = {}, allowedMimes = []) => {
  const detected = detectMime(buffer);
  const allowed = allowedMimes.map(normalizeMime);

  if (!detected || !allowed.includes(detected)) {
    throw new FileValidationError("File content does not match an allowed file type");
  }

  if (mimetype !== undefined && normalizeMime(mimetype) !== detected) {
    throw new FileValidationError("File content does not match the declared file type");
  }

  if (originalname !== undefined) {
    const ext = path.extname(String(originalname)).toLowerCase();
    if (!EXTENSIONS[detected].includes(ext)) {
      throw new FileValidationError("File extension does not match the file content");
    }
  }

  return detected;
};

module.exports = { detectMime, validateFile, normalizeMime, FileValidationError };
