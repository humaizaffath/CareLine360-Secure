const multer = require("multer");
const { validateFile, FileValidationError } = require("../utils/fileSignature");
const { uploadBuffer } = require("../services/uploadService");

/**
 * Build an upload handler that buffers the file in memory, validates its real
 * content (magic bytes + MIME + extension allow-list) and only then uploads it
 * to Cloudinary. Keeps the `.single(field)` API and populates req.file with the
 * same fields multer-storage-cloudinary used to provide (path, filename, ...).
 *
 * @param {object}   config
 * @param {string[]} config.allowedMimes     - allowed MIME types
 * @param {number}   config.maxFileSize      - bytes
 * @param {string}   config.fileFilterError  - message for the metadata pre-check
 * @param {(mime: string) => object} config.cloudinaryOptions - upload options for a detected MIME
 */
const createSecureUpload = ({ allowedMimes, maxFileSize, fileFilterError, cloudinaryOptions }) => {
  const allowed = new Set(allowedMimes);

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxFileSize },
    // Cheap first gate on client metadata; real validation happens on the bytes below
    fileFilter: (req, file, cb) => {
      if (!allowed.has(file.mimetype)) return cb(new Error(fileFilterError));
      cb(null, true);
    },
  });

  const single = (field) => {
    const parse = upload.single(field);

    return (req, res, next) => {
      parse(req, res, async (err) => {
        if (err) return next(err);
        if (!req.file) return next();

        let detected;
        try {
          detected = validateFile(req.file, allowedMimes);
        } catch (e) {
          if (e instanceof FileValidationError) {
            return res.status(e.status).json({ success: false, message: e.message });
          }
          return next(e);
        }

        try {
          const result = await uploadBuffer(req.file.buffer, cloudinaryOptions(detected));
          req.file.path = result.secure_url;
          req.file.filename = result.public_id;
          req.file.resource_type = result.resource_type;
          req.file.format = result.format;
          req.file.version = result.version;
          req.file.mimetype = detected;
          delete req.file.buffer;
          next();
        } catch (e) {
          next(e);
        }
      });
    };
  };

  return { single };
};

module.exports = { createSecureUpload };
