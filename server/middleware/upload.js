const { createSecureUpload } = require("./secureUpload");

// Validates the image's actual content before it is uploaded (V8 / CWE-434)
const imageUpload = createSecureUpload({
  allowedMimes: ["image/jpeg", "image/png", "image/webp"],
  maxFileSize: 2 * 1024 * 1024, // 2MB
  fileFilterError: "Only image files allowed",
  cloudinaryOptions: () => ({
    folder: "careline360/avatars",
    resource_type: "image",
    allowed_formats: ["jpg", "jpeg", "png", "webp"],
    transformation: [{ width: 512, height: 512, crop: "fill" }],
  }),
});

module.exports = { imageUpload };
