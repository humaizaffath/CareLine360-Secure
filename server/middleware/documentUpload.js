const { createSecureUpload } = require("./secureUpload");

const allowed = [
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/webp",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
];

// Validates the file's actual content before it is uploaded (V8 / CWE-434)
const documentUpload = createSecureUpload({
  allowedMimes: allowed,
  maxFileSize: 10 * 1024 * 1024, // 10MB
  fileFilterError: "Only PDF, images, DOC, DOCX allowed",
  cloudinaryOptions: () => ({
    folder: "careline360/documents",
    resource_type: "auto",
  }),
});

module.exports = { documentUpload };
