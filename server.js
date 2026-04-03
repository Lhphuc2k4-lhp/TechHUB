import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import multer from "multer";
import { fileURLToPath } from "url";
import { checkDatabaseConnection, getConnection, query } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadsRoot = path.join(__dirname, "uploads");
const deviceUploadsDir = path.join(uploadsRoot, "devices");

dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
const port = Number(process.env.PORT || 5000);

let deviceImageColumn = "img_url";
let employeeNameColumn = "ho_ten";
let employeeCodeColumn = "ma_nv";
const passwordResetOtps = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;

fs.mkdirSync(deviceUploadsDir, { recursive: true });

const deviceImageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, deviceUploadsDir),
    filename: (_req, file, callback) => {
      const extension = path.extname(file.originalname || "").toLowerCase() || ".png";
      callback(null, `device-${Date.now()}-${crypto.randomBytes(6).toString("hex")}${extension}`);
    },
  }),
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (_req, file, callback) => {
    if (!file.mimetype?.startsWith("image/")) {
      callback(new Error("Chỉ chấp nhận file ảnh."));
      return;
    }

    callback(null, true);
  },
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use("/uploads", express.static(uploadsRoot));

function looksMisencoded(value = "") {
  return /(?:Ã.|Â.|Ä.|Å.|Æ.|áº|á»|â€|â€œ|â€\u009d|â€™)/.test(value);
}

function repairText(value) {
  if (typeof value !== "string") {
    return value;
  }

  let repairedValue = value;

  for (let index = 0; index < 3; index += 1) {
    if (!looksMisencoded(repairedValue)) {
      break;
    }

    const decodedValue = Buffer.from(repairedValue, "latin1").toString("utf8");
    if (!decodedValue || decodedValue === repairedValue) {
      break;
    }

    repairedValue = decodedValue;
  }

  return repairedValue;
}

function repairPayload(payload) {
  if (typeof payload === "string") {
    return repairText(payload);
  }

  if (Array.isArray(payload)) {
    return payload.map(repairPayload);
  }

  if (payload && typeof payload === "object") {
    return Object.fromEntries(Object.entries(payload).map(([key, value]) => [key, repairPayload(value)]));
  }

  return payload;
}

app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (payload) => originalJson(repairPayload(payload));
  next();
});

async function resolveRequestUser(req) {
  const headerUserId = Number(req.headers["x-user-id"]);
  const headerRole = Number(req.headers["x-user-role"]);

  if (!headerUserId || Number.isNaN(headerUserId)) {
    return null;
  }

  const rows = await query(
    `
      SELECT id, role
      FROM nhanvien
      WHERE id = ?
      LIMIT 1
    `,
    [headerUserId]
  );

  if (!rows.length) {
    return null;
  }

  const user = {
    id: Number(rows[0].id),
    role: Number(rows[0].role),
  };

  if (!Number.isNaN(headerRole) && headerRole !== user.role) {
    return null;
  }

  return user;
}

function requireAdmin(handler) {
  return async (req, res, next) => {
    try {
      const user = await resolveRequestUser(req);
      if (!user || user.role !== 0) {
        return res.status(403).json({ message: "Chỉ quản trị viên mới được thực hiện thao tác này." });
      }

      req.authUser = user;
      return handler(req, res, next);
    } catch (error) {
      return res.status(500).json({ message: "Không thể xác thực quyền truy cập.", error: error.message });
    }
  };
}

function requireEmployee(handler) {
  return async (req, res, next) => {
    try {
      const user = await resolveRequestUser(req);
      if (!user) {
        return res.status(401).json({ message: "Bạn cần đăng nhập để thực hiện thao tác này." });
      }

      req.authUser = user;
      return handler(req, res, next);
    } catch (error) {
      return res.status(500).json({ message: "Không thể xác thực quyền truy cập.", error: error.message });
    }
  };
}

function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

function legacyGetMailerConfig() {
  const host = process.env.SMTP_HOST?.trim();
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || "false").toLowerCase() === "true";
  const user = process.env.SMTP_USER?.trim();
  const pass = process.env.SMTP_PASS?.trim();
  const from = process.env.MAIL_FROM?.trim() || user;

  if (!host || !port || !user || !pass || !from) {
    throw new Error("Chưa cấu hình SMTP để gửi mail OTP.");
  }

  return {
    transporter: nodemailer.createTransport({
      host,
      port,
      secure,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
      auth: {
        user,
        pass,
      },
    }),
    from,
  };
}

async function legacySendPasswordResetOtpEmail(email, employeeName, otp) {
  const { transporter, from } = legacyGetMailerConfig();

  await transporter.sendMail({
    from,
    to: email,
    subject: "TechHUB - Mã OTP đặt lại mật khẩu",
    text: `Xin chào ${employeeName}, mã OTP đặt lại mật khẩu của bạn là ${otp}. Mã có hiệu lực trong 10 phút.`,
    html: `
      <div style="font-family: Arial, Helvetica, sans-serif; color: #1f2937; line-height: 1.6;">
        <h2 style="margin-bottom: 8px;">TechHUB - Đặt lại mật khẩu</h2>
        <p>Xin chào <strong>${employeeName}</strong>,</p>
        <p>Bạn vừa yêu cầu đặt lại mật khẩu cho tài khoản nhân viên.</p>
        <p>Mã OTP của bạn là:</p>
        <div style="font-size: 28px; font-weight: 700; letter-spacing: 8px; color: #b42318; margin: 16px 0;">
          ${otp}
        </div>
        <p>Mã này có hiệu lực trong <strong>10 phút</strong>.</p>
        <p>Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.</p>
      </div>
    `,
  });
}

function legacyGetFriendlySmtpErrorMessage(error) {
  const message = String(error?.message || "");
  const normalized = message.toLowerCase();

  if (normalized.includes("timeout")) {
    return "Hết thời gian kết nối khi gửi email. Vui lòng kiểm tra cấu hình máy chủ trên Railway.";
  }

  if (normalized.includes("auth")) {
    return "Máy chủ email đang từ chối đăng nhập. Vui lòng kiểm tra lại tài khoản gửi thư.";
  }

  if (normalized.includes("smtp")) {
    return message;
  }

  return message || "Không thể gửi mã OTP.";
}

function parseMailFrom(value = "") {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    throw new Error("Chưa cấu hình MAIL_FROM trên Railway.");
  }

  const matchedSender = trimmedValue.match(/^(.*)<([^>]+)>$/);
  if (matchedSender) {
    return {
      name: matchedSender[1].trim().replace(/^\"|\"$/g, "") || "TechHUB",
      email: matchedSender[2].trim(),
    };
  }

  return {
    name: "TechHUB",
    email: trimmedValue,
  };
}

async function sendPasswordResetOtpEmail(email, employeeName, otp) {
  const apiKey = process.env.BREVO_API_KEY?.trim();
  const sender = parseMailFrom(process.env.MAIL_FROM?.trim() || "");

  if (!apiKey) {
    throw new Error("Chưa cấu hình BREVO_API_KEY trên Railway.");
  }

  const subject = "TechHUB - Mã OTP đặt lại mật khẩu";
  const textContent = `Xin chào ${employeeName}, mã OTP đặt lại mật khẩu của bạn là ${otp}. Mã có hiệu lực trong 10 phút.`;
  const htmlContent = `
    <div style="font-family: Arial, Helvetica, sans-serif; color: #1f2937; line-height: 1.6;">
      <h2 style="margin-bottom: 8px;">TechHUB - Đặt lại mật khẩu</h2>
      <p>Xin chào <strong>${employeeName}</strong>,</p>
      <p>Bạn vừa yêu cầu đặt lại mật khẩu cho tài khoản nhân viên.</p>
      <p>Mã OTP của bạn là:</p>
      <div style="font-size: 28px; font-weight: 700; letter-spacing: 8px; color: #b42318; margin: 16px 0;">
        ${otp}
      </div>
      <p>Mã này có hiệu lực trong <strong>10 phút</strong>.</p>
      <p>Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.</p>
    </div>
  `;

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "api-key": apiKey,
    },
    body: JSON.stringify({
      sender,
      to: [{ email }],
      subject,
      textContent,
      htmlContent,
    }),
  });

  if (!response.ok) {
    const payload = await response.text();
    throw new Error(`Brevo API error ${response.status}: ${payload}`);
  }
}

function getFriendlySmtpErrorMessage(error) {
  const message = String(error?.message || "");
  const normalized = message.toLowerCase();

  if (normalized.includes("brevo_api_key")) {
    return "Railway chưa có BREVO_API_KEY để gửi email OTP.";
  }

  if (normalized.includes("mail_from")) {
    return "Railway chưa cấu hình MAIL_FROM hợp lệ cho Brevo.";
  }

  if (normalized.includes("unauthorized") || normalized.includes("invalid api key")) {
    return "BREVO_API_KEY không hợp lệ. Vui lòng tạo API key mới trong Brevo.";
  }

  if (normalized.includes("sender")) {
    return "Email gửi chưa được xác minh trên Brevo. Vui lòng vào Senders để xác minh MAIL_FROM.";
  }

  if (normalized.includes("brevo api error")) {
    return message;
  }

  if (normalized.includes("timeout") || normalized.includes("fetch failed")) {
    return "Máy chủ Railway không kết nối được tới Brevo API. Vui lòng redeploy lại và thử lại sau.";
  }

  return message || "Không thể gửi mã OTP qua Brevo.";
}

async function resolveDeviceImageColumn() {
  try {
    const rows = await query(
      `
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'thietbi'
          AND COLUMN_NAME IN ('image_url', 'img_url')
      `,
      [process.env.DB_NAME || "ql_thietbi"]
    );

    const columnNames = rows.map((row) => row.COLUMN_NAME);
    if (columnNames.includes("image_url")) {
      deviceImageColumn = "image_url";
    } else if (columnNames.includes("img_url")) {
      deviceImageColumn = "img_url";
    }
  } catch (_error) {
    deviceImageColumn = "img_url";
  }
}

async function resolveEmployeeColumns() {
  try {
    const rows = await query(
      `
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'nhanvien'
          AND COLUMN_NAME IN ('ho_ten', 'user', 'ma_nv', 'ma_NV')
      `,
      [process.env.DB_NAME || "ql_thietbi"]
    );

    const columnNames = rows.map((row) => row.COLUMN_NAME);
    employeeNameColumn = columnNames.includes("ho_ten") ? "ho_ten" : "user";
    employeeCodeColumn = columnNames.includes("ma_nv") ? "ma_nv" : "ma_NV";
  } catch (_error) {
    employeeNameColumn = "ho_ten";
    employeeCodeColumn = "ma_nv";
  }
}

function normalizeText(value = "") {
  const normalizedValue =
    typeof value === "string"
      ? value
      : value === null || value === undefined
        ? ""
        : String(value);

  return repairText(normalizedValue)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d")
    .replace(/Đ/g, "D")
    .toLowerCase();
}

function normalizeEmployeeCode(value = "") {
  const rawValue = value.trim().toUpperCase();
  if (!rawValue) return "";

  const normalizedValue = rawValue.startsWith("NV") ? rawValue.slice(2) : rawValue;
  return `NV${normalizedValue.trim()}`;
}

function formatDeviceStatusName(value = "") {
  const normalizedValue = normalizeText(value);

  if (normalizedValue === "tot") {
    return "Tốt";
  }

  if (normalizedValue === "hong") {
    return "Hỏng";
  }

  if (normalizedValue === "dang bao tri") {
    return "Đang bảo trì";
  }

  return value;
}

function getTodayDateString() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function isDateBeforeToday(value) {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(String(value).trim())) {
    return false;
  }

  return String(value).trim() < getTodayDateString();
}

function getBorrowedQuantitySql(alias) {
  return `
    COALESCE(
      (
        SELECT SUM(ctpm.so_luong)
        FROM chitietphieumuon ctpm
        INNER JOIN phieumuon pm ON pm.id = ctpm.phieu_muon_id
        WHERE ctpm.thiet_bi_id = ${alias}.id
          AND pm.trang_thai IN ('dang_muon', 'qua_han')
      ),
      0
    )
  `;
}

function buildDeviceSelectSql(
  extraWhereClause = "",
  extraOrderClause = "ORDER BY CAST(SUBSTRING(COALESCE(tb.ma_thiet_bi, 'TB0'), 3) AS UNSIGNED), tb.ma_thiet_bi ASC, tb.id ASC",
  extraLimitClause = ""
) {
  const borrowedQuantitySql = getBorrowedQuantitySql("tb");
  const primaryImageSql = `
    (
      SELECT hatb.image_url
      FROM hinhanhthietbi hatb
      WHERE hatb.thiet_bi_id = tb.id
      ORDER BY hatb.thu_tu ASC, hatb.id ASC
      LIMIT 1
    )
  `;

  return `
    SELECT
      tb.id,
      tb.ma_thiet_bi AS code,
      tb.ten AS name,
      tb.thuong_hieu AS brand,
      tb.model,
      tb.sku,
      tb.mo_ta AS description,
      tb.url_san_pham AS product_url,
      1 AS total_quantity,
      ${primaryImageSql} AS image_url,
      tb.loai_id AS type_id,
      lt.ten_loai AS type_name,
      tb.tinh_trang_id AS status_id,
      tttb.ten_tinh_trang AS status_name,
      CASE WHEN ${borrowedQuantitySql} > 0 THEN 1 ELSE 0 END AS borrowed_quantity,
      CASE
        WHEN tb.tinh_trang_id = 1 AND ${borrowedQuantitySql} = 0 THEN 1
        ELSE 0
      END AS available_quantity
    FROM thietbi tb
    LEFT JOIN loaithietbi lt ON lt.id = tb.loai_id
    LEFT JOIN tinhtrangthietbi tttb ON tttb.id = tb.tinh_trang_id
    ${extraWhereClause}
    ${extraOrderClause}
    ${extraLimitClause}
  `;
}

function mapDevice(row) {
  const repairedRow = repairPayload(row);
  const normalizedStatus = normalizeText(repairedRow.status_name || "");
  const totalQuantity = 1;
  const borrowedQuantity = Number(repairedRow.borrowed_quantity || 0) > 0 ? 1 : 0;
  const availableQuantity = Number(repairedRow.available_quantity || 0) > 0 ? 1 : 0;
  const isBroken = normalizedStatus === "hong";
  const isMaintenance = normalizedStatus === "dang bao tri";
  const isBorrowedOut = normalizedStatus === "tot" && borrowedQuantity > 0 && availableQuantity === 0;
  const statusLabel = isBroken
    ? "Hỏng"
    : isMaintenance
      ? "Cần bảo trì"
      : isBorrowedOut
        ? "Đang mượn"
        : "Sẵn sàng";

  return {
    id: repairedRow.id,
    code: repairedRow.code || "",
    name: repairedRow.name,
    brand: repairedRow.brand || "",
    model: repairedRow.model || "",
    sku: repairedRow.sku || "",
    imageUrl: repairedRow.image_url,
    productUrl: repairedRow.product_url || "",
    typeId: repairedRow.type_id,
    typeName: repairedRow.type_name,
    statusId: repairedRow.status_id,
    statusName: formatDeviceStatusName(repairedRow.status_name),
    totalQuantity,
    borrowedQuantity,
    availableQuantity,
    statusLabel,
    isAvailable: !isBroken && !isMaintenance && availableQuantity > 0,
    description: repairedRow.description || `${repairedRow.name} thuộc nhóm ${repairedRow.type_name}.`,
  };
}

function mapEmployee(row) {
  const repairedRow = repairPayload(row);
  return {
    id: repairedRow.id,
    fullName: repairedRow.full_name,
    username: repairedRow.username,
    email: repairedRow.email,
    role: Number(repairedRow.role),
    roleLabel: Number(repairedRow.role) === 0 ? "Quản trị viên" : "Nhân viên",
    employeeCode: repairedRow.employee_code,
  };
}

function normalizeDevicePayload(body = {}) {
  const rawImageUrl = typeof body.imageUrl === "string" ? body.imageUrl.trim() : "";
  const normalizedImageUrl =
    rawImageUrl && !rawImageUrl.startsWith("data:") && rawImageUrl.length <= 255 ? rawImageUrl : null;
  const galleryImages = Array.isArray(body.galleryImages)
    ? body.galleryImages
        .map((item) => (typeof item === "string" ? item.trim() : ""))
        .filter((item) => item && !item.startsWith("data:") && item.length <= 255)
    : normalizedImageUrl
      ? [normalizedImageUrl]
      : [];

  return {
    code: body.code?.trim(),
    name: body.name?.trim(),
    brand: body.brand?.trim() || null,
    model: body.model?.trim() || null,
    sku: body.sku?.trim() || null,
    description: body.description?.trim() || null,
    imageUrl: normalizedImageUrl,
    galleryImages,
    productUrl: body.productUrl?.trim() || null,
    typeId: Number(body.typeId),
    statusId: Number(body.statusId),
  };
}

async function generateNextDeviceCode() {
  const rows = await query(
    `
      SELECT ma_thiet_bi
      FROM thietbi
      WHERE ma_thiet_bi IS NOT NULL
      ORDER BY CAST(SUBSTRING(ma_thiet_bi, 3) AS UNSIGNED) DESC, ma_thiet_bi DESC
      LIMIT 1
    `
  );

  const lastCode = String(rows[0]?.ma_thiet_bi || "");
  const numericPart = Number(lastCode.replace(/\D/g, "")) || 0;
  const nextCode = numericPart + 1;

  return `TB${String(nextCode).padStart(3, "0")}`;
}

async function validateDevicePayload(payload, deviceId = null) {
  if (!payload.name || !payload.typeId || !payload.statusId) {
    throw new Error("Vui lòng nhập đầy đủ thông tin thiết bị.");
  }

  if (Number.isNaN(payload.typeId) || Number.isNaN(payload.statusId)) {
    throw new Error("Dữ liệu thiết bị không hợp lệ.");
  }

  const typeRows = await query(`SELECT id FROM loaithietbi WHERE id = ? LIMIT 1`, [payload.typeId]);
  if (!typeRows.length) {
    throw new Error("Danh mục thiết bị không tồn tại.");
  }

  const statusRows = await query(`SELECT id FROM tinhtrangthietbi WHERE id = ? LIMIT 1`, [payload.statusId]);
  if (!statusRows.length) {
    throw new Error("Trạng thái thiết bị không tồn tại.");
  }

  const duplicateRows = await query(
    `
      SELECT id
      FROM thietbi
      WHERE (ma_thiet_bi = ? OR (? IS NOT NULL AND sku = ?))
        ${deviceId ? "AND id <> ?" : ""}
      LIMIT 1
    `,
    deviceId ? [payload.code, payload.sku, payload.sku, deviceId] : [payload.code, payload.sku, payload.sku]
  );

  if (duplicateRows.length) {
    throw new Error("Mã thiết bị hoặc SKU đã tồn tại.");
  }
}

async function syncDeviceImages(deviceId, imageUrls = []) {
  const normalizedImages = [...new Set((imageUrls || []).filter(Boolean))];

  await query(`DELETE FROM hinhanhthietbi WHERE thiet_bi_id = ?`, [deviceId]);

  for (let index = 0; index < normalizedImages.length; index += 1) {
    await query(
      `
        INSERT INTO hinhanhthietbi (thiet_bi_id, image_url, thu_tu)
        VALUES (?, ?, ?)
      `,
      [deviceId, normalizedImages[index], index + 1]
    );
  }

  await query(
    `
      UPDATE thietbi
      SET ${deviceImageColumn} = ?
      WHERE id = ?
    `,
    [normalizedImages[0] || null, deviceId]
  );
}

function mapLoanSlip(row) {
  const repairedRow = repairPayload(row);
  let status = repairedRow.status || "dang_muon";

  try {
    status = deriveLoanSlipStatus(repairedRow.status, repairedRow.return_condition);
  } catch (_error) {
    status = repairedRow.status || "dang_muon";
  }

  return {
    id: repairedRow.id,
    slipCode: `PM${String(repairedRow.id).padStart(3, "0")}`,
    borrowerId: repairedRow.borrower_id,
    borrowerName: repairedRow.borrower_name,
    employeeId: repairedRow.employee_id,
    employeeName: repairedRow.employee_name,
    borrowDate: formatDateValue(repairedRow.borrow_date),
    dueDate: formatDateValue(repairedRow.due_date),
    status,
    note: repairedRow.note || "",
    deviceSummary: repairedRow.device_summary || "",
    totalItems: Number(repairedRow.total_items || 0),
  };
}

function mapFineSlip(row) {
  const repairedRow = repairPayload(row);

  return {
    id: repairedRow.id,
    fineCode: `PP${String(repairedRow.id).padStart(3, "0")}`,
    loanSlipId: repairedRow.loan_slip_id,
    loanSlipCode: `PM${String(repairedRow.loan_slip_id).padStart(3, "0")}`,
    borrowerName: repairedRow.borrower_name,
    employeeId: repairedRow.employee_id,
    employeeName: repairedRow.employee_name,
    issuedDate: formatDateValue(repairedRow.issued_date),
    fineType: repairedRow.fine_type,
    amount: Number(repairedRow.amount || 0),
    reason: repairedRow.reason || "",
    paymentStatus: repairedRow.payment_status,
    paymentDate: formatDateValue(repairedRow.payment_date),
    note: repairedRow.note || "",
    deviceSummary: repairedRow.device_summary || "",
  };
}

function getReturnConditionLabel(status) {
  if (status === "hong_hoc") return "Hong hoc";
  if (status === "qua_han") return "Qua han";
  return "Tot";
}

async function syncLoanSlipAfterFinePayment(connection, { loanSlipId, employeeId, paymentStatus, paymentDate }) {
  if (paymentStatus !== "da_thanh_toan") {
    return false;
  }

  const normalizedPaymentDate = paymentDate?.trim() || new Date().toISOString().slice(0, 10);
  const [loanRows] = await connection.execute(
    `
      SELECT pm.id, pm.trang_thai, pt.tinh_trang_sau_khi_tra AS return_condition
      FROM phieumuon pm
      LEFT JOIN phieutra pt ON pt.phieu_muon_id = pm.id
      WHERE pm.id = ?
      LIMIT 1
    `,
    [loanSlipId]
  );

  if (!loanRows.length) {
    throw new Error("KhÃ´ng tÃ¬m tháº¥y phiáº¿u mÆ°á»£n liÃªn quan.");
  }

  const effectiveLoanSlipStatus = deriveLoanSlipStatus(
    loanRows[0].trang_thai,
    loanRows[0].return_condition
  );

  if (!["qua_han", "hong_hoc"].includes(effectiveLoanSlipStatus)) {
    return false;
  }

  await connection.execute(`UPDATE phieumuon SET trang_thai = 'da_tra' WHERE id = ?`, [loanSlipId]);

  const [returnRows] = await connection.execute(
    `
      SELECT id
      FROM phieutra
      WHERE phieu_muon_id = ?
      LIMIT 1
    `,
    [loanSlipId]
  );

  if (returnRows.length) {
    await connection.execute(
      `
        UPDATE phieutra
        SET nhan_vien_id = ?, ngay_tra = ?, tinh_trang_sau_khi_tra = ?, ghi_chu = ?
        WHERE phieu_muon_id = ?
      `,
      [employeeId, normalizedPaymentDate, getReturnConditionLabel("da_tra"), "Hoan tat sau khi thanh toan phieu phat.", loanSlipId]
    );
  } else {
    await connection.execute(
      `
        INSERT INTO phieutra (phieu_muon_id, nhan_vien_id, ngay_tra, tinh_trang_sau_khi_tra, ghi_chu)
        VALUES (?, ?, ?, ?, ?)
      `,
      [loanSlipId, employeeId, normalizedPaymentDate, getReturnConditionLabel("da_tra"), "Hoan tat sau khi thanh toan phieu phat."]
    );
  }

  if (effectiveLoanSlipStatus === "hong_hoc") {
    const [loanItems] = await connection.execute(
      `
        SELECT thiet_bi_id
        FROM chitietphieumuon
        WHERE phieu_muon_id = ?
      `,
      [loanSlipId]
    );

    if (loanItems.length) {
      const placeholders = loanItems.map(() => "?").join(", ");
      await connection.execute(
        `
          UPDATE thietbi
          SET tinh_trang_id = 1
          WHERE id IN (${placeholders})
        `,
        loanItems.map((item) => item.thiet_bi_id)
      );
    }
  }

  return true;
}

function formatDateValue(value) {
  if (!value) return null;

  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value.trim())) {
    return value.trim();
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function parseNumberValue(value) {
  if (value === null || value === undefined) return 0;
  const normalized = String(value).replace(/[^\d.-]/g, "");
  return normalized ? Number(normalized) : 0;
}

function parseCsvLine(line) {
  const values = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const nextChar = line[index + 1];

    if (char === '"' && inQuotes && nextChar === '"') {
      current += '"';
      index += 1;
      continue;
    }

    if (char === '"') {
      inQuotes = !inQuotes;
      continue;
    }

    if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values.map((value) => value.trim());
}

function mapTableRows(headers, rows) {
  return rows
    .filter((row) => row.some((cell) => String(cell || "").trim()))
    .map((row) =>
      headers.reduce((result, header, index) => {
        result[normalizeText(header)] = row[index] ?? "";
        return result;
      }, {})
    );
}

function parseCsvContent(content) {
  const lines = String(content || "")
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .filter((line) => line.trim());

  if (lines.length < 2) {
    return [];
  }

  const headers = parseCsvLine(lines[0]);
  const rows = lines.slice(1).map(parseCsvLine);
  return mapTableRows(headers, rows);
}

function decodeHtmlValue(value = "") {
  return String(value)
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function parseExcelHtmlContent(content) {
  const rowMatches = [...String(content || "").matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];
  if (rowMatches.length < 2) {
    return [];
  }

  const rows = rowMatches.map((match) =>
    [...match[1].matchAll(/<t[hd][^>]*>([\s\S]*?)<\/t[hd]>/gi)].map((cellMatch) =>
      decodeHtmlValue(cellMatch[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim())
    )
  );

  const headers = rows[0];
  return mapTableRows(headers, rows.slice(1));
}

function parseRestoreRows(fileName, content) {
  const normalizedFileName = String(fileName || "").toLowerCase();
  if (normalizedFileName.endsWith(".csv")) {
    return parseCsvContent(content);
  }

  if (normalizedFileName.endsWith(".xls")) {
    return parseExcelHtmlContent(content);
  }

  throw new Error("Chá»‰ há»— trá»£ file CSV hoáº·c XLS Ä‘Æ°á»£c xuáº¥t tá»« há»‡ thá»‘ng.");
}

function pickRowValue(row, keys) {
  for (const key of keys) {
    const value = row[normalizeText(key)];
    if (value !== undefined && String(value).trim() !== "") {
      return String(value).trim();
    }
  }

  return "";
}

function parseSlipCode(value, prefix) {
  const rawValue = String(value || "").trim().toUpperCase();
  if (!rawValue.startsWith(prefix)) return null;
  const numericPart = Number(rawValue.slice(prefix.length));
  return Number.isNaN(numericPart) ? null : numericPart;
}

function deriveLoanSlipStatus(statusValue = "", returnConditionValue = "") {
  const normalizedStatus = normalizeText(statusValue || "");
  const normalizedReturnCondition = normalizeText(returnConditionValue || "");

  if (
    ["hong_hoc", "hong hoc", "hong thiet bi", "hu hong", "hu hong thiet bi"].includes(normalizedStatus) ||
    ["hong_hoc", "hong hoc", "hong thiet bi", "hu hong", "hu hong thiet bi"].includes(normalizedReturnCondition)
  ) {
    return "hong_hoc";
  }

  if (
    ["qua_han", "qua han", "tre_han", "tre han"].includes(normalizedStatus) ||
    ["qua_han", "qua han", "tre_han", "tre han"].includes(normalizedReturnCondition)
  ) {
    return "qua_han";
  }

  if (["da_tra", "da tra"].includes(normalizedStatus)) {
    return "da_tra";
  }

  return "dang_muon";
}

function parseLoanStatus(value) {
  const normalized = normalizeText(value);
  if (normalized.includes("da tra")) return "da_tra";
  if (normalized.includes("hong hoc")) return "hong_hoc";
  if (normalized.includes("qua han")) return "qua_han";
  return "dang_muon";
}

function parsePaymentStatus(value) {
  const normalized = normalizeText(value);
  return normalized.includes("da thanh toan") ? "da_thanh_toan" : "chua_thanh_toan";
}

function parseFineType(value) {
  const normalized = normalizeText(value);
  if (normalized.includes("tre han")) return "tre_han";
  if (normalized.includes("hong")) return "hong_thiet_bi";
  if (normalized.includes("mat")) return "mat_thiet_bi";
  return "khac";
}

function parseDeviceSummary(summary) {
  return String(summary || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const match = part.match(/^(.*)\sx(\d+)$/i);
      if (!match) {
        return { name: part, quantity: 1 };
      }

      return {
        name: match[1].trim(),
        quantity: Number(match[2] || 1),
      };
    });
}

async function getDefaultEmployeeId() {
  const rows = await query(`SELECT id FROM nhanvien ORDER BY id LIMIT 1`);
  if (!rows.length) {
    throw new Error("KhÃ´ng tÃ¬m tháº¥y nhÃ¢n viÃªn nÃ o Ä‘á»ƒ gÃ¡n cho dá»¯ liá»‡u phá»¥c há»“i.");
  }

  return Number(rows[0].id);
}

async function ensureDeviceTypeId(typeName) {
  const trimmedName = String(typeName || "").trim();
  if (!trimmedName) {
    throw new Error("KhÃ´ng xÃ¡c Ä‘á»‹nh Ä‘Æ°á»£c danh má»¥c thiáº¿t bá»‹ trong file phá»¥c há»“i.");
  }

  const existingRows = await query(`SELECT id FROM loaithietbi WHERE ten_loai = ? LIMIT 1`, [trimmedName]);
  if (existingRows.length) {
    return Number(existingRows[0].id);
  }

  const result = await query(`INSERT INTO loaithietbi (ten_loai) VALUES (?)`, [trimmedName]);
  return Number(result.insertId);
}

async function restoreDeviceTypes(rows) {
  let restored = 0;

  for (const row of rows) {
    const name = pickRowValue(row, ["Ten danh muc", "Danh muc", "Name"]);
    if (!name) continue;
    await ensureDeviceTypeId(name);
    restored += 1;
  }

  return restored;
}

async function restoreDevices(rows) {
  let restored = 0;

  for (const row of rows) {
    const code = pickRowValue(row, ["Ma", "Ma thiet bi", "Code"]);
    const name = pickRowValue(row, ["Thiet bi", "Ten thiet bi", "Name"]);
    const typeName = pickRowValue(row, ["Danh muc", "Ten danh muc", "Loai"]);
    if (!code || !name || !typeName) continue;

    const typeId = await ensureDeviceTypeId(typeName);
    const statusLabel = pickRowValue(row, ["Trang thai", "Status"]);
    const statusId = normalizeText(statusLabel).includes("bao tri") ? 2 : 1;
    const payload = {
      code,
      name,
      brand: pickRowValue(row, ["Thuong hieu", "Brand"]) || null,
      model: pickRowValue(row, ["Model"]) || null,
      sku: pickRowValue(row, ["SKU"]) || null,
      description: pickRowValue(row, ["Mo ta", "Description"]) || null,
      imageUrl: pickRowValue(row, ["Anh", "Anh dai dien", "Image"]) || null,
      productUrl: pickRowValue(row, ["Link san pham", "Product URL"]) || null,
      typeId,
      statusId,
    };

    const existingRows = await query(
      `
        SELECT id
        FROM thietbi
        WHERE ma_thiet_bi = ? OR (? IS NOT NULL AND sku = ?)
        LIMIT 1
      `,
      [payload.code, payload.sku, payload.sku]
    );

    if (existingRows.length) {
      await validateDevicePayload(payload, Number(existingRows[0].id));
      await query(
        `
          UPDATE thietbi
          SET
            ma_thiet_bi = ?,
            ten = ?,
            loai_id = ?,
            thuong_hieu = ?,
            model = ?,
            sku = ?,
            mo_ta = ?,
            url_san_pham = ?,
            tinh_trang_id = ?,
            ${deviceImageColumn} = ?
          WHERE id = ?
        `,
        [
          payload.code,
          payload.name,
          payload.typeId,
          payload.brand,
          payload.model,
          payload.sku,
          payload.description,
          payload.productUrl,
          payload.statusId,
          payload.imageUrl,
          Number(existingRows[0].id),
        ]
      );
    } else {
      await validateDevicePayload(payload);
      await query(
        `
          INSERT INTO thietbi (
            ma_thiet_bi,
            ten,
            loai_id,
            thuong_hieu,
            model,
            sku,
            mo_ta,
            url_san_pham,
            tinh_trang_id,
            ${deviceImageColumn}
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          payload.code,
          payload.name,
          payload.typeId,
          payload.brand,
          payload.model,
          payload.sku,
          payload.description,
          payload.productUrl,
          payload.statusId,
          payload.imageUrl,
        ]
      );
    }

    restored += 1;
  }

  return restored;
}

async function buildBorrowerMap() {
  const rows = await query(`SELECT id, ten FROM nguoimuon`);
  return new Map(rows.map((row) => [normalizeText(row.ten), Number(row.id)]));
}

async function ensureBorrowerId(connection, borrowerName) {
  const trimmedBorrowerName = String(borrowerName || "").trim();
  if (!trimmedBorrowerName) {
    throw new Error("Vui lÃ²ng nháº­p tÃªn ngÆ°á»i mÆ°á»£n.");
  }

  const [borrowerRows] = await connection.execute(`SELECT id, ten FROM nguoimuon`);
  const matchedBorrower = borrowerRows.find((row) => normalizeText(row.ten) === normalizeText(trimmedBorrowerName));

  if (matchedBorrower) {
    return Number(matchedBorrower.id);
  }

  const [insertResult] = await connection.execute(`INSERT INTO nguoimuon (ten) VALUES (?)`, [trimmedBorrowerName]);
  return Number(insertResult.insertId);
}

async function resolveBorrowerId(connection, borrowerId, borrowerName) {
  if (borrowerName) {
    return ensureBorrowerId(connection, borrowerName);
  }

  if (!borrowerId) {
    throw new Error("Vui lÃ²ng nháº­p Ä‘áº§y Ä‘á»§ thÃ´ng tin phiáº¿u mÆ°á»£n.");
  }

  const [borrowerRows] = await connection.execute(`SELECT id FROM nguoimuon WHERE id = ? LIMIT 1`, [borrowerId]);
  if (!borrowerRows.length) {
    throw new Error("NgÆ°á»i mÆ°á»£n khÃ´ng tá»“n táº¡i.");
  }

  return Number(borrowerRows[0].id);
}

async function buildDeviceMapByName() {
  const rows = await query(`SELECT id, ten FROM thietbi`);
  return new Map(rows.map((row) => [normalizeText(row.ten), Number(row.id)]));
}

async function restoreLoanSlips(rows) {
  const borrowerMap = await buildBorrowerMap();
  const deviceMap = await buildDeviceMapByName();
  const employeeId = await getDefaultEmployeeId();
  const connection = await getConnection();
  let restored = 0;

  try {
    await connection.beginTransaction();

    for (const row of rows) {
      const slipCode = pickRowValue(row, ["Ma phieu", "Slip Code"]);
      const borrowerName = pickRowValue(row, ["Nguoi muon", "Borrower"]);
      const deviceSummary = pickRowValue(row, ["Thiet bi", "Device Summary"]);
      const borrowDate = formatDateValue(pickRowValue(row, ["Ngay muon", "Borrow Date"]));
      const dueDate = formatDateValue(pickRowValue(row, ["Han tra", "Due Date"]));
      const status = parseLoanStatus(pickRowValue(row, ["Trang thai", "Status"]));
      const borrowerId = borrowerMap.get(normalizeText(borrowerName));

      if (!borrowerId || !deviceSummary || !borrowDate || !dueDate) continue;

      const items = parseDeviceSummary(deviceSummary)
        .map((item) => ({ ...item, deviceId: deviceMap.get(normalizeText(item.name)) }))
        .filter((item) => item.deviceId && item.quantity > 0);

      if (!items.length) continue;

      const loanSlipId = parseSlipCode(slipCode, "PM");
      const [existingRows] = loanSlipId
        ? await connection.execute(`SELECT id FROM phieumuon WHERE id = ? LIMIT 1`, [loanSlipId])
        : [[]];

      if (existingRows.length) {
        await connection.execute(
          `UPDATE phieumuon SET nguoi_muon_id = ?, nhan_vien_id = ?, ngay_muon = ?, han_tra = ?, trang_thai = ?, ghi_chu = NULL WHERE id = ?`,
          [borrowerId, employeeId, borrowDate, dueDate, status, loanSlipId]
        );
        await connection.execute(`DELETE FROM chitietphieumuon WHERE phieu_muon_id = ?`, [loanSlipId]);
      } else if (loanSlipId) {
        await connection.execute(
          `INSERT INTO phieumuon (id, nguoi_muon_id, nhan_vien_id, ngay_muon, han_tra, trang_thai, ghi_chu) VALUES (?, ?, ?, ?, ?, ?, NULL)`,
          [loanSlipId, borrowerId, employeeId, borrowDate, dueDate, status]
        );
      } else {
        const [insertResult] = await connection.execute(
          `INSERT INTO phieumuon (nguoi_muon_id, nhan_vien_id, ngay_muon, han_tra, trang_thai, ghi_chu) VALUES (?, ?, ?, ?, ?, NULL)`,
          [borrowerId, employeeId, borrowDate, dueDate, status]
        );
        row.__generatedLoanId = Number(insertResult.insertId);
      }

      const targetLoanId = loanSlipId || row.__generatedLoanId;
      for (const item of items) {
        await connection.execute(
          `INSERT INTO chitietphieumuon (phieu_muon_id, thiet_bi_id, so_luong, tinh_trang_luc_muon, ghi_chu) VALUES (?, ?, ?, 'Tot', NULL)`,
          [targetLoanId, item.deviceId, item.quantity]
        );
      }

      if (["dang_muon", "qua_han"].includes(status)) {
        await connection.execute(`DELETE FROM phieutra WHERE phieu_muon_id = ?`, [targetLoanId]);
      } else {
        const [returnRows] = await connection.execute(`SELECT id FROM phieutra WHERE phieu_muon_id = ? LIMIT 1`, [targetLoanId]);
        if (returnRows.length) {
          await connection.execute(
            `UPDATE phieutra SET nhan_vien_id = ?, ngay_tra = ?, tinh_trang_sau_khi_tra = ?, ghi_chu = NULL WHERE phieu_muon_id = ?`,
            [employeeId, dueDate, getReturnConditionLabel(status), targetLoanId]
          );
        } else {
          await connection.execute(
            `INSERT INTO phieutra (phieu_muon_id, nhan_vien_id, ngay_tra, tinh_trang_sau_khi_tra, ghi_chu) VALUES (?, ?, ?, ?, NULL)`,
            [targetLoanId, employeeId, dueDate, getReturnConditionLabel(status)]
          );
        }
      }

      if (status === "hong_hoc") {
        const damagedIds = items.map((item) => item.deviceId);
        const placeholders = damagedIds.map(() => "?").join(", ");
        await connection.execute(`UPDATE thietbi SET tinh_trang_id = 2 WHERE id IN (${placeholders})`, damagedIds);
      }

      restored += 1;
    }

    await connection.commit();
    return restored;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

async function restoreFineSlips(rows) {
  const employeeId = await getDefaultEmployeeId();
  const connection = await getConnection();
  let restored = 0;

  try {
    await connection.beginTransaction();

    for (const row of rows) {
      const fineCode = pickRowValue(row, ["Ma phieu phat", "Ma phieu", "Fine Code"]);
      const loanSlipCode = pickRowValue(row, ["Phieu muon", "Loan Slip"]);
      const issuedDate = formatDateValue(pickRowValue(row, ["Ngay phat", "Issued Date"]));
      const fineType = parseFineType(pickRowValue(row, ["Loai phat", "Fine Type"]));
      const amount = parseNumberValue(pickRowValue(row, ["So tien", "Amount"]));
      const paymentStatus = parsePaymentStatus(pickRowValue(row, ["Thanh toan", "Payment"]));
      const fineId = parseSlipCode(fineCode, "PP");
      const loanSlipId = parseSlipCode(loanSlipCode, "PM");

      if (!loanSlipId || !issuedDate) continue;

      const [loanRows] = await connection.execute(`SELECT id FROM phieumuon WHERE id = ? LIMIT 1`, [loanSlipId]);
      if (!loanRows.length) continue;

      const [existingRows] = fineId
        ? await connection.execute(`SELECT id FROM phieuphat WHERE id = ? LIMIT 1`, [fineId])
        : await connection.execute(`SELECT id FROM phieuphat WHERE phieu_muon_id = ? LIMIT 1`, [loanSlipId]);

      const reason = pickRowValue(row, ["Ly do", "Reason"]) || null;
      const note = pickRowValue(row, ["Ghi chu", "Note"]) || null;
      const paymentDate = paymentStatus === "da_thanh_toan" ? issuedDate : null;

      if (existingRows.length) {
        await connection.execute(
          `
            UPDATE phieuphat
            SET phieu_muon_id = ?, nhan_vien_id = ?, ngay_phat = ?, loai_phat = ?, so_tien_phat = ?, ly_do = ?, trang_thai_thanh_toan = ?, ngay_thanh_toan = ?, ghi_chu = ?
            WHERE id = ?
          `,
          [loanSlipId, employeeId, issuedDate, fineType, amount, reason, paymentStatus, paymentDate, note, Number(existingRows[0].id)]
        );
      } else if (fineId) {
        await connection.execute(
          `
            INSERT INTO phieuphat (id, phieu_muon_id, nhan_vien_id, ngay_phat, loai_phat, so_tien_phat, ly_do, trang_thai_thanh_toan, ngay_thanh_toan, ghi_chu)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [fineId, loanSlipId, employeeId, issuedDate, fineType, amount, reason, paymentStatus, paymentDate, note]
        );
      } else {
        await connection.execute(
          `
            INSERT INTO phieuphat (phieu_muon_id, nhan_vien_id, ngay_phat, loai_phat, so_tien_phat, ly_do, trang_thai_thanh_toan, ngay_thanh_toan, ghi_chu)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [loanSlipId, employeeId, issuedDate, fineType, amount, reason, paymentStatus, paymentDate, note]
        );
      }

      restored += 1;
    }

    await connection.commit();
    return restored;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

app.get("/api/health", async (_req, res) => {
  try {
    await checkDatabaseConnection();
    res.json({ ok: true, message: "Connected to database" });
  } catch (error) {
    res.status(500).json({ ok: false, message: "Database connection failed", error: error.message });
  }
});

async function handleLogin(req, res) {
  try {
    const source = req.method === "GET" ? req.query : req.body;
    const identifier = source.identifier?.trim();
    const password = source.password?.trim();

    if (!identifier || !password) {
      return res.status(400).json({ message: "Vui lòng nhập tài khoản và mật khẩu." });
    }

    const rows = await query(
      `
        SELECT
          id,
          ${employeeNameColumn} AS full_name,
          username,
          password_admin,
          email,
          role,
          ${employeeCodeColumn} AS employee_code
        FROM nhanvien
        WHERE username = ? OR email = ?
        LIMIT 1
      `,
      [identifier, identifier]
    );

    if (!rows.length) {
      return res.status(401).json({ message: "Tài khoản không tồn tại." });
    }

    const employee = rows[0];
    if (String(employee.password_admin) !== String(password)) {
      return res.status(401).json({ message: "Mật khẩu không đúng." });
    }

    return res.json({ message: "Đăng nhập thành công.", user: mapEmployee(employee) });
  } catch (error) {
    return res.status(500).json({ message: "Không thể đăng nhập.", error: error.message });
  }
}

app.get("/api/auth/login", handleLogin);
app.post("/api/auth/login", handleLogin);

app.post("/api/auth/forgot-password/request", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Vui lòng nhập email để nhận mã OTP." });
    }

    const rows = await query(
      `
        SELECT
          id,
          ${employeeNameColumn} AS full_name,
          email
        FROM nhanvien
        WHERE LOWER(email) = ?
        LIMIT 1
      `,
      [email]
    );

    if (!rows.length) {
      return res.status(404).json({ message: "Email này không tồn tại trong hệ thống." });
    }

    const employee = rows[0];
    const otp = generateOtp();

    passwordResetOtps.set(email, {
      employeeId: employee.id,
      otpHash: hashOtp(otp),
      expiresAt: Date.now() + OTP_TTL_MS,
    });

    await sendPasswordResetOtpEmail(employee.email, employee.full_name, otp);

    return res.json({
      message: "Đã gửi mã OTP qua email. Vui lòng kiểm tra hộp thư của bạn.",
    });
  } catch (error) {
    const friendlyMessage = getFriendlySmtpErrorMessage(error);
    const normalizedMessage = friendlyMessage.toLowerCase();
    const statusCode =
      normalizedMessage.includes("brevo") ||
      normalizedMessage.includes("sender") ||
      normalizedMessage.includes("timeout") ||
      normalizedMessage.includes("redeploy")
        ? 503
        : 500;
    return res.status(statusCode).json({ message: friendlyMessage, error: error.message });
  }
});

app.post("/api/auth/forgot-password/reset", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const otp = req.body.otp?.trim();
    const newPassword = req.body.newPassword?.trim();

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ email, mã OTP và mật khẩu mới." });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự." });
    }

    const otpRecord = passwordResetOtps.get(email);
    if (!otpRecord) {
      return res.status(400).json({ message: "Mã OTP không tồn tại hoặc đã hết hạn." });
    }

    if (otpRecord.expiresAt < Date.now()) {
      passwordResetOtps.delete(email);
      return res.status(400).json({ message: "Mã OTP đã hết hạn. Vui lòng yêu cầu mã mới." });
    }

    if (otpRecord.otpHash !== hashOtp(otp)) {
      return res.status(400).json({ message: "Mã OTP không đúng." });
    }

    const rows = await query(`SELECT id FROM nhanvien WHERE id = ? AND LOWER(email) = ? LIMIT 1`, [
      otpRecord.employeeId,
      email,
    ]);

    if (!rows.length) {
      passwordResetOtps.delete(email);
      return res.status(404).json({ message: "Không tìm thấy tài khoản cần đặt lại mật khẩu." });
    }

    await query(`UPDATE nhanvien SET password_admin = ? WHERE id = ?`, [newPassword, otpRecord.employeeId]);
    passwordResetOtps.delete(email);

    return res.json({ message: "Đặt lại mật khẩu thành công. Bạn có thể đăng nhập lại ngay bây giờ." });
  } catch (error) {
    return res.status(500).json({ message: "Không thể đặt lại mật khẩu.", error: error.message });
  }
});

app.get("/api/employees", requireAdmin(async (req, res) => {
  try {
    const role = req.query.role ? Number(req.query.role) : null;
    const filters = [];
    const params = [];

    if (role !== null && !Number.isNaN(role)) {
      filters.push("role = ?");
      params.push(role);
    }

    const rows = await query(
      `
        SELECT
          id,
          ${employeeNameColumn} AS full_name,
          username,
          email,
          role,
          ${employeeCodeColumn} AS employee_code
        FROM nhanvien
        ${filters.length ? `WHERE ${filters.join(" AND ")}` : ""}
        ORDER BY id
      `,
      params
    );

    return res.json(rows.map(mapEmployee));
  } catch (error) {
    return res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c danh sÃ¡ch nhÃ¢n viÃªn.", error: error.message });
  }
}));

app.post("/api/employees", requireAdmin(async (req, res) => {
  try {
    const fullName = req.body.fullName?.trim();
    const username = req.body.username?.trim();
    const password = req.body.password?.trim();
    const email = req.body.email?.trim();
    const role = Number(req.body.role);
    const employeeCode = normalizeEmployeeCode(req.body.employeeCode || "");

    if (!fullName || !username || !password || !email || !employeeCode || Number.isNaN(role)) {
      return res.status(400).json({ message: "Vui lÃ²ng nháº­p Ä‘áº§y Ä‘á»§ thÃ´ng tin tÃ i khoáº£n." });
    }

    if (role !== 1) {
      return res.status(400).json({ message: "Chá»‰ Ä‘Æ°á»£c cáº¥p thÃªm tÃ i khoáº£n nhÃ¢n viÃªn." });
    }

    const duplicatedRows = await query(
      `
        SELECT id
        FROM nhanvien
        WHERE username = ? OR email = ? OR ${employeeCodeColumn} = ?
        LIMIT 1
      `,
      [username, email, employeeCode]
    );

    if (duplicatedRows.length) {
      return res.status(400).json({ message: "Username, email hoáº·c mÃ£ nhÃ¢n viÃªn Ä‘Ã£ tá»“n táº¡i." });
    }

    await query(
      `
        INSERT INTO nhanvien (${employeeNameColumn}, username, password_admin, email, role, ${employeeCodeColumn})
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [fullName, username, password, email, role, employeeCode]
    );

    return res.status(201).json({ message: "Táº¡o tÃ i khoáº£n thÃ nh cÃ´ng." });
  } catch (error) {
    return res.status(500).json({ message: "KhÃ´ng thá»ƒ táº¡o tÃ i khoáº£n.", error: error.message });
  }
}));

app.get("/api/employees/:id", requireEmployee(async (req, res) => {
  try {
    const employeeId = Number(req.params.id);
    if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
      return res.status(403).json({ message: "Bạn không có quyền xem thông tin tài khoản này." });
    }

    const rows = await query(
      `
        SELECT
          id,
          ${employeeNameColumn} AS full_name,
          username,
          email,
          role,
          ${employeeCodeColumn} AS employee_code
        FROM nhanvien
        WHERE id = ?
        LIMIT 1
      `,
      [employeeId]
    );

    if (!rows.length) {
      return res.status(404).json({ message: "KhÃ´ng tÃ¬m tháº¥y nhÃ¢n viÃªn." });
    }

    return res.json(mapEmployee(rows[0]));
  } catch (error) {
    return res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c thÃ´ng tin tÃ i khoáº£n.", error: error.message });
  }
}));

app.put("/api/employees/:id", requireEmployee(async (req, res) => {
  try {
    const employeeId = Number(req.params.id);
    const fullName = req.body.fullName?.trim();
    const email = req.body.email?.trim().toLowerCase();

    if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
      return res.status(403).json({ message: "Bạn không có quyền cập nhật tài khoản này." });
    }

    if (!fullName || !email) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ họ tên và email." });
    }

    const rows = await query(`SELECT id, role FROM nhanvien WHERE id = ? LIMIT 1`, [employeeId]);
    if (!rows.length) {
      return res.status(404).json({ message: "Không tìm thấy nhân viên." });
    }

    const duplicateRows = await query(`SELECT id FROM nhanvien WHERE LOWER(email) = ? AND id <> ? LIMIT 1`, [email, employeeId]);
    if (duplicateRows.length) {
      return res.status(400).json({ message: "Email này đã được sử dụng bởi tài khoản khác." });
    }

    await query(`UPDATE nhanvien SET ${employeeNameColumn} = ?, email = ? WHERE id = ?`, [fullName, email, employeeId]);

    const updatedRows = await query(
      `
        SELECT
          id,
          ${employeeNameColumn} AS full_name,
          username,
          email,
          role,
          ${employeeCodeColumn} AS employee_code
        FROM nhanvien
        WHERE id = ?
        LIMIT 1
      `,
      [employeeId]
    );

    return res.json({
      message: "Cập nhật thông tin tài khoản thành công.",
      user: mapEmployee(updatedRows[0]),
    });
  } catch (error) {
    return res.status(500).json({ message: "Không thể cập nhật tài khoản.", error: error.message });
  }
}));

app.delete("/api/employees/:id", requireAdmin(async (req, res) => {
  try {
    const employeeId = Number(req.params.id);

    if (Number.isNaN(employeeId)) {
      return res.status(400).json({ message: "ID nhÃ¢n viÃªn khÃ´ng há»£p lá»‡." });
    }

    const rows = await query(`SELECT id, role FROM nhanvien WHERE id = ? LIMIT 1`, [employeeId]);

    if (!rows.length) {
      return res.status(404).json({ message: "KhÃ´ng tÃ¬m tháº¥y tÃ i khoáº£n cáº§n xÃ³a." });
    }

    if (Number(rows[0].role) === 0) {
      return res.status(400).json({ message: "KhÃ´ng Ä‘Æ°á»£c xÃ³a tÃ i khoáº£n quáº£n trá»‹." });
    }

    const [loanRows, fineRows] = await Promise.all([
      query(`SELECT COUNT(*) AS total FROM phieumuon WHERE nhan_vien_id = ?`, [employeeId]).catch(() => [{ total: 0 }]),
      query(`SELECT COUNT(*) AS total FROM phieuphat WHERE nhan_vien_id = ?`, [employeeId]).catch(() => [{ total: 0 }]),
    ]);

    if (Number(loanRows[0]?.total || 0) > 0 || Number(fineRows[0]?.total || 0) > 0) {
      return res.status(400).json({
        message: "TÃ i khoáº£n nÃ y Ä‘Ã£ Ä‘Æ°á»£c sá»­ dá»¥ng trong phiáº¿u mÆ°á»£n hoáº·c phiáº¿u pháº¡t, khÃ´ng thá»ƒ xÃ³a.",
      });
    }

    await query(`DELETE FROM nhanvien WHERE id = ?`, [employeeId]);
    return res.json({ message: "ÄÃ£ xÃ³a tÃ i khoáº£n nhÃ¢n viÃªn thÃ nh cÃ´ng." });
  } catch (error) {
    return res.status(500).json({ message: "KhÃ´ng thá»ƒ xÃ³a tÃ i khoáº£n.", error: error.message });
  }
}));

app.put("/api/employees/:id/password", requireEmployee(async (req, res) => {
  try {
    const employeeId = Number(req.params.id);
    const currentPassword = req.body.currentPassword?.trim();
    const newPassword = req.body.newPassword?.trim();

    if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
      return res.status(403).json({ message: "Bạn không có quyền đổi mật khẩu cho tài khoản này." });
    }

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Vui lÃ²ng nháº­p Ä‘á»§ máº­t kháº©u hiá»‡n táº¡i vÃ  máº­t kháº©u má»›i." });
    }

    const rows = await query(`SELECT id, password_admin FROM nhanvien WHERE id = ? LIMIT 1`, [employeeId]);

    if (!rows.length) {
      return res.status(404).json({ message: "KhÃ´ng tÃ¬m tháº¥y nhÃ¢n viÃªn." });
    }

    if (String(rows[0].password_admin) !== String(currentPassword)) {
      return res.status(400).json({ message: "Máº­t kháº©u hiá»‡n táº¡i khÃ´ng Ä‘Ãºng." });
    }

    await query(`UPDATE nhanvien SET password_admin = ? WHERE id = ?`, [newPassword, employeeId]);
    return res.json({ message: "Äá»•i máº­t kháº©u thÃ nh cÃ´ng." });
  } catch (error) {
    return res.status(500).json({ message: "KhÃ´ng thá»ƒ Ä‘á»•i máº­t kháº©u.", error: error.message });
  }
}));

app.get("/api/borrowers", async (_req, res) => {
  try {
    const rows = await query(
      `
        SELECT id, ten AS name, email, so_dien_thoai AS phone
        FROM nguoimuon
        ORDER BY id
      `
    );

    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c danh sÃ¡ch ngÆ°á»i mÆ°á»£n.", error: error.message });
  }
});

app.get("/api/device-types", async (_req, res) => {
  try {
    const rows = await query(
      `
        SELECT
          lt.id,
          lt.ten_loai AS name,
          COUNT(tb.id) AS total_devices
        FROM loaithietbi lt
        LEFT JOIN thietbi tb ON tb.loai_id = lt.id
        GROUP BY lt.id, lt.ten_loai
        ORDER BY lt.id
      `
    );

    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c loáº¡i thiáº¿t bá»‹.", error: error.message });
  }
});

app.get("/api/device-statuses", async (_req, res) => {
  try {
    const rows = await query(
      `
        SELECT id, ten_tinh_trang AS name
        FROM tinhtrangthietbi
        ORDER BY id
      `
    );

    res.json(rows.map((row) => ({ ...row, name: formatDeviceStatusName(row.name) })));
  } catch (error) {
    res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c tráº¡ng thÃ¡i thiáº¿t bá»‹.", error: error.message });
  }
});

app.get("/api/dashboard/summary", async (_req, res) => {
  try {
    const borrowedQuantitySql = getBorrowedQuantitySql("tb");

    const [deviceRows, employeeRows, typeRows] = await Promise.all([
      query(
        `
          SELECT
            COUNT(*) AS total_devices,
            SUM(CASE WHEN tb.tinh_trang_id = 1 AND ${borrowedQuantitySql} = 0 THEN 1 ELSE 0 END) AS ready_devices,
            SUM(CASE WHEN tb.tinh_trang_id <> 1 OR ${borrowedQuantitySql} > 0 THEN 1 ELSE 0 END) AS maintenance_devices
          FROM thietbi tb
        `
      ),
      query(
        `
          SELECT
            COUNT(*) AS total_employees,
            SUM(CASE WHEN role = 0 THEN 1 ELSE 0 END) AS total_admins,
            SUM(CASE WHEN role = 1 THEN 1 ELSE 0 END) AS total_staff
          FROM nhanvien
        `
      ),
      query(
        `
          SELECT
            lt.ten_loai AS label,
            COUNT(tb.id) AS total
          FROM loaithietbi lt
          LEFT JOIN thietbi tb ON tb.loai_id = lt.id
          GROUP BY lt.id, lt.ten_loai
          ORDER BY lt.id
        `
      ),
    ]);

    res.json({
      totals: {
        totalDevices: Number(deviceRows[0]?.total_devices || 0),
        readyDevices: Number(deviceRows[0]?.ready_devices || 0),
        maintenanceDevices: Number(deviceRows[0]?.maintenance_devices || 0),
        totalEmployees: Number(employeeRows[0]?.total_employees || 0),
        totalAdmins: Number(employeeRows[0]?.total_admins || 0),
        totalStaff: Number(employeeRows[0]?.total_staff || 0),
      },
      deviceTypeStats: typeRows.map((row) => ({ label: row.label, total: Number(row.total || 0) })),
    });
  } catch (error) {
    res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c dá»¯ liá»‡u dashboard.", error: error.message });
  }
});

app.get("/api/devices", async (req, res) => {
  try {
    const typeId = req.query.typeId ? Number(req.query.typeId) : null;
    const statusId = req.query.statusId ? Number(req.query.statusId) : null;
    const search = req.query.search?.trim() || "";
    const filters = [];
    const params = [];

    if (typeId) {
      filters.push("tb.loai_id = ?");
      params.push(typeId);
    }

    if (statusId) {
      filters.push("tb.tinh_trang_id = ?");
      params.push(statusId);
    }

    if (search) {
      filters.push("tb.ten LIKE ?");
      params.push(`%${search}%`);
    }

    const rows = await query(buildDeviceSelectSql(filters.length ? `WHERE ${filters.join(" AND ")}` : ""), params);
    res.json(rows.map(mapDevice));
  } catch (error) {
    res.status(500).json({ message: "Không lấy được danh sách thiết bị.", error: error.message });
  }
});

app.post(
  "/api/uploads/device-image",
  requireAdmin((req, res) => {
    deviceImageUpload.single("image")(req, res, (error) => {
      if (error) {
        const message =
          error.code === "LIMIT_FILE_SIZE"
            ? "Ảnh tải lên quá lớn. Vui lòng chọn ảnh nhỏ hơn 5MB."
            : error.message || "Không thể tải ảnh lên.";
        return res.status(400).json({ message });
      }

      if (!req.file) {
        return res.status(400).json({ message: "Vui lòng chọn một file ảnh." });
      }

      const imageUrl = `${req.protocol}://${req.get("host")}/uploads/devices/${req.file.filename}`;
      return res.status(201).json({
        message: "Tải ảnh lên thành công.",
        imageUrl,
      });
    });
  })
);

app.post("/api/devices", requireAdmin(async (req, res) => {
  try {
    const payload = normalizeDevicePayload(req.body);
    payload.code = await generateNextDeviceCode();
    await validateDevicePayload(payload);

    const result = await query(
      `
        INSERT INTO thietbi (
          ma_thiet_bi,
          ten,
          loai_id,
          thuong_hieu,
          model,
          sku,
          mo_ta,
          url_san_pham,
          tinh_trang_id,
          ${deviceImageColumn}
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        payload.code,
        payload.name,
        payload.typeId,
        payload.brand,
        payload.model,
        payload.sku,
        payload.description,
        payload.productUrl,
        payload.statusId,
        null,
      ]
    );

    await syncDeviceImages(result.insertId, payload.galleryImages);

    return res.status(201).json({ message: "Thêm thiết bị thành công.", id: result.insertId });
  } catch (error) {
    const statusCode = error?.code === "ER_DATA_TOO_LONG" ? 400 : 500;
    const fallbackMessage =
      error?.code === "ER_DATA_TOO_LONG"
        ? "Dữ liệu ảnh quá dài. Vui lòng dùng link ảnh ngắn hơn hoặc bỏ ảnh rồi thử lại."
        : "Không thể thêm thiết bị.";
    return res.status(statusCode).json({ message: error.message || fallbackMessage, error: error.message });
  }
}));

app.get("/api/devices/:id", async (req, res) => {
  try {
    const deviceId = Number(req.params.id);
    const rows = await query(buildDeviceSelectSql("WHERE tb.id = ?", "", "LIMIT 1"), [deviceId]);

    if (!rows.length) {
      return res.status(404).json({ message: "Không tìm thấy thiết bị." });
    }

    const device = mapDevice(rows[0]);
    const imageRows = await query(
      `
        SELECT image_url
        FROM hinhanhthietbi
        WHERE thiet_bi_id = ?
        ORDER BY thu_tu ASC, id ASC
      `,
      [deviceId]
    );
    const relatedRows = await query(
      buildDeviceSelectSql("WHERE tb.loai_id = ? AND tb.id <> ?", "ORDER BY tb.id", "LIMIT 4"),
      [device.typeId, device.id]
    );

    return res.json({
      ...device,
      galleryImages: imageRows.map((row) => repairPayload(row).image_url).filter(Boolean),
      relatedDevices: relatedRows.map(mapDevice),
    });
  } catch (error) {
    return res.status(500).json({ message: "Không lấy được chi tiết thiết bị.", error: error.message });
  }
});

app.put("/api/devices/:id", requireAdmin(async (req, res) => {
  try {
    const deviceId = Number(req.params.id);
    const payload = normalizeDevicePayload(req.body);

    const existingRows = await query(buildDeviceSelectSql("WHERE tb.id = ?", "", "LIMIT 1"), [deviceId]);
    if (!existingRows.length) {
      return res.status(404).json({ message: "Không tìm thấy thiết bị." });
    }

    await validateDevicePayload(payload, deviceId);

    await query(
      `
        UPDATE thietbi
        SET
          ma_thiet_bi = ?,
          ten = ?,
          loai_id = ?,
          thuong_hieu = ?,
          model = ?,
          sku = ?,
          mo_ta = ?,
          url_san_pham = ?,
          tinh_trang_id = ?,
          ${deviceImageColumn} = ?
        WHERE id = ?
      `,
      [
        payload.code,
        payload.name,
        payload.typeId,
        payload.brand,
        payload.model,
        payload.sku,
        payload.description,
        payload.productUrl,
        payload.statusId,
        null,
        deviceId,
      ]
    );

    await syncDeviceImages(deviceId, payload.galleryImages);

    return res.json({
      message: "Cập nhật thiết bị thành công.",
    });
  } catch (error) {
    const statusCode = error?.code === "ER_DATA_TOO_LONG" ? 400 : 500;
    const fallbackMessage =
      error?.code === "ER_DATA_TOO_LONG"
        ? "Dữ liệu ảnh quá dài. Vui lòng dùng link ảnh ngắn hơn hoặc bỏ ảnh rồi thử lại."
        : "Không thể cập nhật thiết bị.";
    return res.status(statusCode).json({ message: error.message || fallbackMessage, error: error.message });
  }
}));

app.delete("/api/devices/:id", requireAdmin(async (req, res) => {
  const connection = await getConnection();

  try {
    const deviceId = Number(req.params.id);

    await connection.beginTransaction();

    const [rows] = await connection.execute(`SELECT id, ten FROM thietbi WHERE id = ? LIMIT 1`, [deviceId]);
    if (!rows.length) {
      await connection.rollback();
      return res.status(404).json({ message: "Không tìm thấy thiết bị." });
    }

    const [activeBorrowRows] = await connection.execute(
      `
        SELECT COALESCE(SUM(ctpm.so_luong), 0) AS borrowed_quantity
        FROM chitietphieumuon ctpm
        INNER JOIN phieumuon pm ON pm.id = ctpm.phieu_muon_id
        WHERE ctpm.thiet_bi_id = ?
          AND pm.trang_thai IN ('dang_muon', 'qua_han')
      `,
      [deviceId]
    );

    if (Number(activeBorrowRows[0]?.borrowed_quantity || 0) > 0) {
      await connection.rollback();
      return res.status(400).json({ message: "Thiết bị đang nằm trong phiếu mượn, không thể xóa." });
    }

    await connection.execute(`DELETE FROM chitietphieumuon WHERE thiet_bi_id = ?`, [deviceId]);
    await connection.execute(`DELETE FROM thietbi WHERE id = ?`, [deviceId]);

    await connection.commit();
    return res.json({ message: "Xóa thiết bị thành công." });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: error.message || "Không thể xóa thiết bị.", error: error.message });
  } finally {
    connection.release();
  }
}));

app.get("/api/loan-slips", async (req, res) => {
  try {
    const search = req.query.search?.trim() || "";
    const filters = [];
    const params = [];

    if (search) {
      filters.push("(nm.ten LIKE ? OR tb.ten LIKE ? OR pm.id LIKE ?)");
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const rows = await query(
      `
        SELECT
          pm.id,
          pm.nguoi_muon_id AS borrower_id,
          nm.ten AS borrower_name,
          pm.nhan_vien_id AS employee_id,
          nv.${employeeNameColumn} AS employee_name,
          pm.ngay_muon AS borrow_date,
          pm.han_tra AS due_date,
          pm.trang_thai AS status,
          pt.tinh_trang_sau_khi_tra AS return_condition,
          pm.ghi_chu AS note,
          COUNT(ctpm.thiet_bi_id) AS total_items,
          GROUP_CONCAT(CONCAT(tb.ten, ' x', ctpm.so_luong) ORDER BY tb.ten SEPARATOR ', ') AS device_summary
        FROM phieumuon pm
        LEFT JOIN nguoimuon nm ON nm.id = pm.nguoi_muon_id
        LEFT JOIN nhanvien nv ON nv.id = pm.nhan_vien_id
        LEFT JOIN phieutra pt ON pt.phieu_muon_id = pm.id
        LEFT JOIN chitietphieumuon ctpm ON ctpm.phieu_muon_id = pm.id
        LEFT JOIN thietbi tb ON tb.id = ctpm.thiet_bi_id
        ${filters.length ? `WHERE ${filters.join(" AND ")}` : ""}
        GROUP BY pm.id, pm.nguoi_muon_id, nm.ten, pm.nhan_vien_id, nv.${employeeNameColumn}, pm.ngay_muon, pm.han_tra, pm.trang_thai, pt.tinh_trang_sau_khi_tra, pm.ghi_chu
        ORDER BY pm.id DESC
      `,
      params
    );

    res.json(rows.map(mapLoanSlip));
  } catch (error) {
    res.status(500).json({ message: "KhÃ´ng láº¥y Ä‘Æ°á»£c danh sÃ¡ch phiáº¿u mÆ°á»£n.", error: error.message });
  }
});

app.post("/api/loan-slips", requireEmployee(async (req, res) => {
  const borrowerId = Number(req.body.borrowerId);
  const borrowerName = req.body.borrowerName?.trim() || "";
  const employeeId = Number(req.body.employeeId);
  const borrowDate = req.body.borrowDate?.trim();
  const dueDate = req.body.dueDate?.trim();
  const note = req.body.note?.trim() || null;
  const items = Array.isArray(req.body.items) ? req.body.items : [];

  if ((!borrowerId && !borrowerName) || !employeeId || !borrowDate || !dueDate || !items.length) {
    return res.status(400).json({ message: "Vui lÃ²ng nháº­p Ä‘áº§y Ä‘á»§ thÃ´ng tin phiáº¿u mÆ°á»£n." });
  }

  if (isDateBeforeToday(borrowDate) || isDateBeforeToday(dueDate)) {
    return res.status(400).json({ message: "Ngày mượn và hạn trả không được nhỏ hơn ngày hiện tại." });
  }

  if (dueDate < borrowDate) {
    return res.status(400).json({ message: "Hạn trả không được nhỏ hơn ngày mượn." });
  }

  if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
    return res.status(403).json({ message: "Bạn không có quyền lập phiếu mượn cho nhân viên khác." });
  }

  const normalizedItems = items
    .map((item) => ({ deviceId: Number(item.deviceId), quantity: 1, note: item.note?.trim() || null }))
    .filter((item) => item.deviceId);

  if (!normalizedItems.length) {
    return res.status(400).json({ message: "Phiáº¿u mÆ°á»£n cáº§n Ã­t nháº¥t má»™t thiáº¿t bá»‹ há»£p lá»‡." });
  }

  const uniqueDeviceIds = [...new Set(normalizedItems.map((item) => item.deviceId))];
  if (uniqueDeviceIds.length !== normalizedItems.length) {
    return res.status(400).json({ message: "Má»—i thiáº¿t bá»‹ chá»‰ nÃªn xuáº¥t hiá»‡n má»™t láº§n trong phiáº¿u." });
  }

  const connection = await getConnection();

  try {
    await connection.beginTransaction();

    const placeholders = uniqueDeviceIds.map(() => "?").join(", ");
    const [deviceRows] = await connection.execute(
      buildDeviceSelectSql(`WHERE tb.id IN (${placeholders})`, "", ""),
      uniqueDeviceIds
    );

    const deviceMap = new Map(deviceRows.map((row) => [Number(row.id), mapDevice(row)]));

    for (const item of normalizedItems) {
      const matchedDevice = deviceMap.get(item.deviceId);

      if (!matchedDevice) {
        throw new Error("CÃ³ thiáº¿t bá»‹ khÃ´ng tá»“n táº¡i trong há»‡ thá»‘ng.");
      }

      if (!matchedDevice.isAvailable) {
        throw new Error(`Thiáº¿t bá»‹ "${matchedDevice.name}" hiá»‡n khÃ´ng sáºµn sÃ ng Ä‘á»ƒ mÆ°á»£n.`);
      }

      if (matchedDevice.availableQuantity < 1) {
        throw new Error(`Thiáº¿t bá»‹ "${matchedDevice.name}" khÃ´ng cÃ²n sáºµn Ä‘á»ƒ mÆ°á»£n.`);
      }
    }

    const resolvedBorrowerId = await resolveBorrowerId(connection, borrowerId, borrowerName);

    const [slipResult] = await connection.execute(
      `
        INSERT INTO phieumuon (nguoi_muon_id, nhan_vien_id, ngay_muon, han_tra, trang_thai, ghi_chu)
        VALUES (?, ?, ?, ?, 'dang_muon', ?)
      `,
      [resolvedBorrowerId, employeeId, borrowDate, dueDate, note]
    );

    for (const item of normalizedItems) {
      const matchedDevice = deviceMap.get(item.deviceId);

      await connection.execute(
        `
          INSERT INTO chitietphieumuon (phieu_muon_id, thiet_bi_id, so_luong, tinh_trang_luc_muon, ghi_chu)
          VALUES (?, ?, ?, ?, ?)
        `,
        [slipResult.insertId, item.deviceId, 1, matchedDevice.statusName || "Tot", item.note]
      );
    }

    await connection.commit();
    return res.status(201).json({ message: "Láº­p phiáº¿u mÆ°á»£n thÃ nh cÃ´ng.", id: slipResult.insertId });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: error.message || "KhÃ´ng thá»ƒ láº­p phiáº¿u mÆ°á»£n.", error: error.message });
  } finally {
    connection.release();
  }
}));

app.put("/api/loan-slips/:id/status", requireEmployee(async (req, res) => {
  const slipId = Number(req.params.id);
  const employeeId = Number(req.body.employeeId);
  const status = req.body.status?.trim();
  const note = req.body.note?.trim() || null;
  const returnDate = req.body.returnDate?.trim() || new Date().toISOString().slice(0, 10);

  if (!slipId || !employeeId || !status) {
    return res.status(400).json({ message: "Vui lòng nhập đầy đủ thông tin cập nhật phiếu mượn." });
  }

  if (!["da_tra", "hong_hoc", "qua_han"].includes(status)) {
    return res.status(400).json({ message: "Trạng thái cập nhật không hợp lệ." });
  }

  if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
    return res.status(403).json({ message: "Bạn không có quyền xử lý phiếu mượn cho nhân viên khác." });
  }

  const connection = await getConnection();

  try {
    await connection.beginTransaction();

    const [slipRows] = await connection.execute(
      `
        SELECT id, trang_thai, han_tra
        FROM phieumuon
        WHERE id = ?
        LIMIT 1
      `,
      [slipId]
    );

    if (!slipRows.length) {
      throw new Error("Không tìm thấy phiếu mượn.");
    }

    const currentStatus = slipRows[0].trang_thai;
    const dueDate = String(slipRows[0].han_tra || "").slice(0, 10);
    if (["da_tra", "hong_hoc"].includes(currentStatus)) {
      throw new Error("Phiếu mượn này đã được xác nhận trả.");
    }

    if (currentStatus === "qua_han" && status === "da_tra") {
      throw new Error("Phiếu mượn quá hạn chỉ được chuyển sang đã trả sau khi thanh toán phiếu phạt.");
    }

    const [loanItems] = await connection.execute(
      `
        SELECT thiet_bi_id
        FROM chitietphieumuon
        WHERE phieu_muon_id = ?
      `,
      [slipId]
    );

    await connection.execute(`UPDATE phieumuon SET trang_thai = ?, ghi_chu = ? WHERE id = ?`, [status, note, slipId]);

    if (status === "qua_han") {
      await connection.execute(`DELETE FROM phieutra WHERE phieu_muon_id = ?`, [slipId]);
    } else {
      const [existingReturnRows] = await connection.execute(
        `
          SELECT id
          FROM phieutra
          WHERE phieu_muon_id = ?
          LIMIT 1
        `,
        [slipId]
      );

      if (existingReturnRows.length) {
        await connection.execute(
          `
            UPDATE phieutra
            SET nhan_vien_id = ?, ngay_tra = ?, tinh_trang_sau_khi_tra = ?, ghi_chu = ?
            WHERE phieu_muon_id = ?
          `,
          [employeeId, returnDate, getReturnConditionLabel(status), note, slipId]
        );
      } else {
        await connection.execute(
          `
            INSERT INTO phieutra (phieu_muon_id, nhan_vien_id, ngay_tra, tinh_trang_sau_khi_tra, ghi_chu)
            VALUES (?, ?, ?, ?, ?)
          `,
          [slipId, employeeId, returnDate, getReturnConditionLabel(status), note]
        );
      }
    }

    if (status === "hong_hoc" && loanItems.length) {
      const placeholders = loanItems.map(() => "?").join(", ");
      await connection.execute(
        `
          UPDATE thietbi
          SET tinh_trang_id = 2
          WHERE id IN (${placeholders})
        `,
        loanItems.map((item) => item.thiet_bi_id)
      );
    }

    await connection.commit();
    if (status === "da_tra") {
      return res.json({ message: "Cập nhật phiếu mượn sang đã trả thành công." });
    }

    if (status === "qua_han") {
      return res.json({ message: "Đã đánh dấu phiếu mượn quá hạn và tiếp tục giữ thiết bị." });
    }

    return res.json({
      message: status === "da_tra" ? "Cập nhật phiếu mượn sang đã trả thành công." : "Đã ghi nhận phiếu mượn hỏng hóc.",
    });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: error.message || "Không thể cập nhật phiếu mượn.", error: error.message });
  } finally {
    connection.release();
  }
}));

app.get("/api/fine-slips", async (req, res) => {
  try {
    const search = req.query.search?.trim() || "";
    const filters = [];
    const params = [];

    if (search) {
      filters.push("(nm.ten LIKE ? OR tb.ten LIKE ? OR pp.id LIKE ? OR pm.id LIKE ? OR pp.ly_do LIKE ?)");
      params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }

    const rows = await query(
      `
        SELECT
          pp.id,
          pp.phieu_muon_id AS loan_slip_id,
          pp.nhan_vien_id AS employee_id,
          nv.${employeeNameColumn} AS employee_name,
          nm.ten AS borrower_name,
          pp.ngay_phat AS issued_date,
          pp.loai_phat AS fine_type,
          pp.so_tien_phat AS amount,
          pp.ly_do AS reason,
          pp.trang_thai_thanh_toan AS payment_status,
          pp.ngay_thanh_toan AS payment_date,
          pp.ghi_chu AS note,
          GROUP_CONCAT(CONCAT(tb.ten, ' x', ctpm.so_luong) ORDER BY tb.ten SEPARATOR ', ') AS device_summary
        FROM phieuphat pp
        INNER JOIN phieumuon pm ON pm.id = pp.phieu_muon_id
        LEFT JOIN nguoimuon nm ON nm.id = pm.nguoi_muon_id
        LEFT JOIN nhanvien nv ON nv.id = pp.nhan_vien_id
        LEFT JOIN chitietphieumuon ctpm ON ctpm.phieu_muon_id = pm.id
        LEFT JOIN thietbi tb ON tb.id = ctpm.thiet_bi_id
        ${filters.length ? `WHERE ${filters.join(" AND ")}` : ""}
        GROUP BY pp.id, pp.phieu_muon_id, pp.nhan_vien_id, nv.${employeeNameColumn}, nm.ten, pp.ngay_phat, pp.loai_phat, pp.so_tien_phat, pp.ly_do, pp.trang_thai_thanh_toan, pp.ngay_thanh_toan, pp.ghi_chu
        ORDER BY pp.id DESC
      `,
      params
    );

    return res.json(rows.map(mapFineSlip));
  } catch (error) {
    return res.status(500).json({ message: "Không lấy được danh sách phiếu phạt.", error: error.message });
  }
});

app.post("/api/fine-slips", requireEmployee(async (req, res) => {
  const connection = await getConnection();

  try {
    const loanSlipId = Number(req.body.loanSlipId);
    const employeeId = Number(req.body.employeeId);
    const issuedDate = req.body.issuedDate?.trim();
    const fineType = req.body.fineType?.trim();
    const amount = Number(req.body.amount);
    const reason = req.body.reason?.trim() || null;
    const paymentStatus = req.body.paymentStatus?.trim() || "chua_thanh_toan";
    const paymentDate = req.body.paymentDate?.trim() || null;
    const note = req.body.note?.trim() || null;

    if (!loanSlipId || !employeeId || !issuedDate || !fineType || Number.isNaN(amount)) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ thông tin phiếu phạt." });
    }

    if (isDateBeforeToday(issuedDate) || (paymentDate && isDateBeforeToday(paymentDate))) {
      return res.status(400).json({ message: "Ngày phạt và ngày thanh toán không được nhỏ hơn ngày hiện tại." });
    }

    if (paymentDate && paymentDate < issuedDate) {
      return res.status(400).json({ message: "Ngày thanh toán không được nhỏ hơn ngày phạt." });
    }

    if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
      return res.status(403).json({ message: "Bạn không có quyền lập phiếu phạt cho nhân viên khác." });
    }

    await connection.beginTransaction();

    const [loanSlipRows] = await connection.execute(
      `
        SELECT pm.id, pm.trang_thai, pt.tinh_trang_sau_khi_tra AS return_condition
        FROM phieumuon pm
        LEFT JOIN phieutra pt ON pt.phieu_muon_id = pm.id
        WHERE pm.id = ?
        LIMIT 1
      `,
      [loanSlipId]
    );

    if (!loanSlipRows.length) {
      await connection.rollback();
      return res.status(404).json({ message: "Không tìm thấy phiếu mượn." });
    }

    const effectiveLoanSlipStatus = deriveLoanSlipStatus(
      loanSlipRows[0].trang_thai,
      loanSlipRows[0].return_condition
    );

    if (!["qua_han", "hong_hoc"].includes(effectiveLoanSlipStatus)) {
      await connection.rollback();
      return res.status(400).json({ message: "Chỉ có thể lập phiếu phạt cho phiếu mượn quá hạn hoặc hỏng hóc." });
    }

    const [existingFineRows] = await connection.execute(`SELECT id FROM phieuphat WHERE phieu_muon_id = ? LIMIT 1`, [loanSlipId]);
    if (existingFineRows.length) {
      await connection.rollback();
      return res.status(400).json({ message: "Phiếu mượn này đã được lập phiếu phạt." });
    }

    await connection.execute(
      `
        INSERT INTO phieuphat (
          phieu_muon_id,
          nhan_vien_id,
          ngay_phat,
          loai_phat,
          so_tien_phat,
          ly_do,
          trang_thai_thanh_toan,
          ngay_thanh_toan,
          ghi_chu
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [loanSlipId, employeeId, issuedDate, fineType, amount, reason, paymentStatus, paymentDate, note]
    );

    const didSyncLoanSlip = await syncLoanSlipAfterFinePayment(connection, {
      loanSlipId,
      employeeId,
      paymentStatus,
      paymentDate,
    });

    await connection.commit();

    return res.status(201).json({
      message: didSyncLoanSlip
        ? "Tạo phiếu phạt thành công và đã cập nhật phiếu mượn sang đã trả."
        : "Tạo phiếu phạt thành công.",
    });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: "Không thể tạo phiếu phạt.", error: error.message });
  } finally {
    connection.release();
  }
}));

app.put("/api/fine-slips/:id", requireEmployee(async (req, res) => {
  const connection = await getConnection();

  try {
    const fineId = Number(req.params.id);
    const loanSlipId = Number(req.body.loanSlipId);
    const employeeId = Number(req.body.employeeId);
    const issuedDate = req.body.issuedDate?.trim();
    const fineType = req.body.fineType?.trim();
    const amount = Number(req.body.amount);
    const reason = req.body.reason?.trim() || null;
    const paymentStatus = req.body.paymentStatus?.trim() || "chua_thanh_toan";
    const paymentDate = req.body.paymentDate?.trim() || null;
    const note = req.body.note?.trim() || null;

    if (!fineId || !loanSlipId || !employeeId || !issuedDate || !fineType || Number.isNaN(amount)) {
      return res.status(400).json({ message: "Vui lòng nhập đầy đủ thông tin phiếu phạt." });
    }

    if (req.authUser.role !== 0 && req.authUser.id !== employeeId) {
      return res.status(403).json({ message: "Bạn không có quyền cập nhật phiếu phạt cho nhân viên khác." });
    }

    await connection.beginTransaction();

    const [existingRows] = await connection.execute(`SELECT id FROM phieuphat WHERE id = ? LIMIT 1`, [fineId]);
    if (!existingRows.length) {
      await connection.rollback();
      return res.status(404).json({ message: "Không tìm thấy phiếu phạt." });
    }

    const [duplicateLoanSlipRows] = await connection.execute(
      `SELECT id FROM phieuphat WHERE phieu_muon_id = ? AND id <> ? LIMIT 1`,
      [loanSlipId, fineId]
    );
    if (duplicateLoanSlipRows.length) {
      await connection.rollback();
      return res.status(400).json({ message: "Phiếu mượn này đã được lập phiếu phạt." });
    }

    const [loanSlipRows] = await connection.execute(
      `
        SELECT pm.id, pm.trang_thai, pt.tinh_trang_sau_khi_tra AS return_condition
        FROM phieumuon pm
        LEFT JOIN phieutra pt ON pt.phieu_muon_id = pm.id
        WHERE pm.id = ?
        LIMIT 1
      `,
      [loanSlipId]
    );

    if (!loanSlipRows.length) {
      await connection.rollback();
      return res.status(404).json({ message: "Không tìm thấy phiếu mượn." });
    }

    const effectiveLoanSlipStatus = deriveLoanSlipStatus(
      loanSlipRows[0].trang_thai,
      loanSlipRows[0].return_condition
    );

    if (!["qua_han", "hong_hoc"].includes(effectiveLoanSlipStatus)) {
      await connection.rollback();
      return res.status(400).json({ message: "Chỉ có thể cập nhật phiếu phạt cho phiếu mượn quá hạn hoặc hỏng hóc." });
    }

    await connection.execute(
      `
        UPDATE phieuphat
        SET
          phieu_muon_id = ?,
          nhan_vien_id = ?,
          ngay_phat = ?,
          loai_phat = ?,
          so_tien_phat = ?,
          ly_do = ?,
          trang_thai_thanh_toan = ?,
          ngay_thanh_toan = ?,
          ghi_chu = ?
        WHERE id = ?
      `,
      [loanSlipId, employeeId, issuedDate, fineType, amount, reason, paymentStatus, paymentDate, note, fineId]
    );

    const didSyncLoanSlip = await syncLoanSlipAfterFinePayment(connection, {
      loanSlipId,
      employeeId,
      paymentStatus,
      paymentDate,
    });

    await connection.commit();

    return res.json({
      message: didSyncLoanSlip
        ? "Cập nhật phiếu phạt thành công và đã cập nhật phiếu mượn sang đã trả."
        : "Cập nhật phiếu phạt thành công.",
    });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: "Không thể cập nhật phiếu phạt.", error: error.message });
  } finally {
    connection.release();
  }
}));

app.delete("/api/fine-slips/:id", requireAdmin(async (req, res) => {
  try {
    const fineId = Number(req.params.id);
    const existingRows = await query(`SELECT id FROM phieuphat WHERE id = ? LIMIT 1`, [fineId]);
    if (!existingRows.length) {
      return res.status(404).json({ message: "Không tìm thấy phiếu phạt." });
    }

    await query(`DELETE FROM phieuphat WHERE id = ?`, [fineId]);
    return res.json({ message: "Xóa phiếu phạt thành công." });
  } catch (error) {
    return res.status(500).json({ message: "Không thể xóa phiếu phạt.", error: error.message });
  }
}));

app.post("/api/restore", requireAdmin(async (req, res) => {
  try {
    const target = req.body.target?.trim();
    const fileName = req.body.fileName?.trim();
    const content = req.body.content;

    if (!target || !fileName || typeof content !== "string") {
      return res.status(400).json({ message: "Vui lòng gửi đầy đủ mục phục hồi và nội dung file." });
    }

    const rows = parseRestoreRows(fileName, content);
    if (!rows.length) {
      return res.status(400).json({ message: "Không đọc được dữ liệu hợp lệ từ file đã chọn." });
    }

    let restoredCount = 0;

    if (target === "loan_slips") {
      restoredCount = await restoreLoanSlips(rows);
    } else if (target === "fine_slips") {
      restoredCount = await restoreFineSlips(rows);
    } else if (target === "device_types") {
      restoredCount = await restoreDeviceTypes(rows);
    } else if (target === "devices") {
      restoredCount = await restoreDevices(rows);
    } else {
      return res.status(400).json({ message: "Loại dữ liệu phục hồi không hợp lệ." });
    }

    if (!restoredCount) {
      return res.status(400).json({
        message: "Không có dòng nào được phục hồi. Hãy kiểm tra đúng file đã xuất từ hệ thống và dữ liệu tham chiếu hiện có.",
      });
    }

    return res.json({ message: `Phục hồi thành công ${restoredCount} dòng dữ liệu cho mục ${target}.` });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Không thể phục hồi dữ liệu.", error: error.message });
  }
}));

Promise.all([resolveDeviceImageColumn(), resolveEmployeeColumns()]).finally(() => {
  app.listen(port, () => {
    console.log(`Backend is running on http://localhost:${port}`);
  });
});
