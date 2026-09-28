/**
 * V8 - Insecure File Upload (CWE-434)
 * Unit tests for magic-byte based file validation.
 */
jest.mock("../../../config/cloudinary", () => ({
  uploader: {
    upload_stream: jest.fn((opts, cb) => {
      const stream = require("stream");
      const writable = new stream.Writable({ write(chunk, enc, next) { next(); } });
      writable.on("finish", () =>
        cb(null, { secure_url: "https://res.cloudinary.com/test/avatar.png", public_id: "avatar_id" })
      );
      return writable;
    }),
  },
}));

const cloudinary = require("../../../config/cloudinary");
const { detectMime, validateFile } = require("../../../utils/fileSignature");
const { uploadBase64Image } = require("../../../services/uploadService");

const PDF = Buffer.from("%PDF-1.4\n%test\n");
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10]);
const WEBP = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBPVP8 ")]);
const DOC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0]);
const DOCX = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("....word/document.xml")]);
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("....payload.bin")]);
const TEXT = Buffer.from("this is plain text, not a pdf");
const HTML = Buffer.from("<html><body>not an image</body></html>");

const DOC_TYPES = [
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/webp",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
];

describe("V8 fileSignature.detectMime", () => {
  test.each([
    [PDF, "application/pdf"],
    [PNG, "image/png"],
    [JPEG, "image/jpeg"],
    [WEBP, "image/webp"],
    [DOC, "application/msword"],
    [DOCX, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  ])("detects genuine file type %#", (buf, mime) => {
    expect(detectMime(buf)).toBe(mime);
  });

  test("returns null for unknown / empty content", () => {
    expect(detectMime(TEXT)).toBeNull();
    expect(detectMime(HTML)).toBeNull();
    expect(detectMime(ZIP)).toBeNull();
    expect(detectMime(Buffer.alloc(0))).toBeNull();
    expect(detectMime(undefined)).toBeNull();
  });
});

describe("V8 fileSignature.validateFile", () => {
  test("accepts genuine files with matching MIME and extension", () => {
    expect(validateFile({ buffer: PDF, mimetype: "application/pdf", originalname: "r.pdf" }, DOC_TYPES))
      .toBe("application/pdf");
    expect(validateFile({ buffer: JPEG, mimetype: "image/jpg", originalname: "a.JPG" }, DOC_TYPES))
      .toBe("image/jpeg");
    expect(
      validateFile(
        {
          buffer: DOCX,
          mimetype: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          originalname: "cv.docx",
        },
        DOC_TYPES
      )
    ).toBe("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
  });

  test("rejects plain text disguised as a PDF (spoofed Content-Type)", () => {
    expect(() =>
      validateFile({ buffer: TEXT, mimetype: "application/pdf", originalname: "report.pdf" }, DOC_TYPES)
    ).toThrow("File content does not match an allowed file type");
  });

  test("rejects HTML disguised as a PNG", () => {
    expect(() =>
      validateFile({ buffer: HTML, mimetype: "image/png", originalname: "x.png" }, ["image/png"])
    ).toThrow(/allowed file type/);
  });

  test("rejects a real file whose declared MIME differs from its content", () => {
    expect(() =>
      validateFile({ buffer: PNG, mimetype: "application/pdf", originalname: "x.pdf" }, DOC_TYPES)
    ).toThrow("File content does not match the declared file type");
  });

  test("rejects a mismatched file extension", () => {
    expect(() =>
      validateFile({ buffer: PDF, mimetype: "application/pdf", originalname: "report.html" }, DOC_TYPES)
    ).toThrow("File extension does not match the file content");
  });

  test("rejects a real file type that is not allow-listed", () => {
    expect(() =>
      validateFile({ buffer: PDF, mimetype: "application/pdf", originalname: "r.pdf" }, ["image/png"])
    ).toThrow(/allowed file type/);
  });

  test("rejects a generic ZIP disguised as DOCX", () => {
    expect(() =>
      validateFile(
        {
          buffer: ZIP,
          mimetype: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          originalname: "cv.docx",
        },
        DOC_TYPES
      )
    ).toThrow(/allowed file type/);
  });

  test("rejected errors carry HTTP 400", () => {
    try {
      validateFile({ buffer: TEXT, mimetype: "application/pdf" }, DOC_TYPES);
    } catch (e) {
      expect(e.status).toBe(400);
    }
    expect.assertions(1);
  });
});

describe("V8 uploadBase64Image content validation", () => {
  const dataUri = (mime, buf) => `data:${mime};base64,${buf.toString("base64")}`;

  test("rejects HTML labelled as image/png and never calls Cloudinary", async () => {
    await expect(uploadBase64Image(dataUri("image/png", HTML))).rejects.toThrow(
      "Image content does not match an allowed image type"
    );
    expect(cloudinary.uploader.upload_stream).not.toHaveBeenCalled();
  });

  test("rejects a JPEG labelled as PNG", async () => {
    await expect(uploadBase64Image(dataUri("image/png", JPEG))).rejects.toThrow(/does not match/);
  });

  test("uploads a genuine PNG", async () => {
    const result = await uploadBase64Image(dataUri("image/png", PNG));
    expect(result).toEqual({ url: "https://res.cloudinary.com/test/avatar.png", publicId: "avatar_id" });
    expect(cloudinary.uploader.upload_stream).toHaveBeenCalledTimes(1);
  });
});
