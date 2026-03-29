import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import { checkDatabaseConnection, getConnection, query } from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
const port = Number(process.env.PORT || 5000);

let deviceImageColumn = "img_url";
let employeeNameColumn = "ho_ten";
let employeeCodeColumn = "ma_nv";
const passwordResetOtps = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;

app.use(cors());
app.use(express.json());

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
    return "Connection timeout khi ket noi SMTP. Vui long kiem tra SMTP_HOST, SMTP_PORT va SMTP_SECURE tren Railway.";
  }

  if (normalized.includes("auth")) {
    return "SMTP dang tu choi dang nhap. Vui long kiem tra SMTP_USER va SMTP_PASS.";
  }

  if (normalized.includes("smtp")) {
    return message;
  }

  return message || "Khong the gui ma OTP.";
}

function parseMailFrom(value = "") {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    throw new Error("Chua cau hinh MAIL_FROM tren Railway.");
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
    throw new Error("Chua cau hinh BREVO_API_KEY tren Railway.");
  }

  const subject = "TechHUB - Ma OTP dat lai mat khau";
  const textContent = `Xin chao ${employeeName}, ma OTP dat lai mat khau cua ban la ${otp}. Ma co hieu luc trong 10 phut.`;
  const htmlContent = `
    <div style="font-family: Arial, Helvetica, sans-serif; color: #1f2937; line-height: 1.6;">
      <h2 style="margin-bottom: 8px;">TechHUB - Dat lai mat khau</h2>
      <p>Xin chao <strong>${employeeName}</strong>,</p>
      <p>Ban vua yeu cau dat lai mat khau cho tai khoan nhan vien.</p>
      <p>Ma OTP cua ban la:</p>
      <div style="font-size: 28px; font-weight: 700; letter-spacing: 8px; color: #b42318; margin: 16px 0;">
        ${otp}
      </div>
      <p>Ma nay co hieu luc trong <strong>10 phut</strong>.</p>
      <p>Neu ban khong thuc hien yeu cau nay, vui long bo qua email.</p>
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
    return "Railway chua co BREVO_API_KEY de gui email OTP.";
  }

  if (normalized.includes("mail_from")) {
    return "Railway chua cau hinh MAIL_FROM hop le cho Brevo.";
  }

  if (normalized.includes("unauthorized") || normalized.includes("invalid api key")) {
    return "BREVO_API_KEY khong hop le. Vui long tao API key moi trong Brevo.";
  }

  if (normalized.includes("sender")) {
    return "Email gui chua duoc xac minh tren Brevo. Vui long vao Senders de verify MAIL_FROM.";
  }

  if (normalized.includes("brevo api error")) {
    return message;
  }

  if (normalized.includes("timeout") || normalized.includes("fetch failed")) {
    return "Server Railway khong ket noi duoc toi Brevo API. Vui long redeploy lai va thu lai sau.";
  }

  return message || "Khong the gui ma OTP qua Brevo.";
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
  return value
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

function getBorrowedQuantitySql(alias) {
  return `
    COALESCE(
      (
        SELECT SUM(ctpm.so_luong)
        FROM chitietphieumuon ctpm
        INNER JOIN phieumuon pm ON pm.id = ctpm.phieu_muon_id
        WHERE ctpm.thiet_bi_id = ${alias}.id
          AND pm.trang_thai = 'dang_muon'
      ),
      0
    )
  `;
}

function buildDeviceSelectSql(extraWhereClause = "", extraOrderClause = "ORDER BY tb.id", extraLimitClause = "") {
  const borrowedQuantitySql = getBorrowedQuantitySql("tb");

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
      tb.tong_so_luong AS total_quantity,
      tb.${deviceImageColumn} AS image_url,
      tb.loai_id AS type_id,
      lt.ten_loai AS type_name,
      tb.tinh_trang_id AS status_id,
      tttb.ten_tinh_trang AS status_name,
      ${borrowedQuantitySql} AS borrowed_quantity,
      GREATEST(tb.tong_so_luong - ${borrowedQuantitySql}, 0) AS available_quantity
    FROM thietbi tb
    LEFT JOIN loaithietbi lt ON lt.id = tb.loai_id
    LEFT JOIN tinhtrangthietbi tttb ON tttb.id = tb.tinh_trang_id
    ${extraWhereClause}
    ${extraOrderClause}
    ${extraLimitClause}
  `;
}

function mapDevice(row) {
  const normalizedStatus = normalizeText(row.status_name || "");
  const totalQuantity = Number(row.total_quantity || 0);
  const borrowedQuantity = Number(row.borrowed_quantity || 0);
  const availableQuantity = Number(row.available_quantity ?? totalQuantity);
  const isMaintenance = normalizedStatus !== "tot";
  const isBorrowedOut = !isMaintenance && borrowedQuantity > 0 && availableQuantity === 0;
  const statusLabel = isMaintenance ? "Can bao tri" : isBorrowedOut ? "Dang muon" : "San sang";

  return {
    id: row.id,
    code: row.code || "",
    name: row.name,
    brand: row.brand || "",
    model: row.model || "",
    sku: row.sku || "",
    imageUrl: row.image_url,
    productUrl: row.product_url || "",
    typeId: row.type_id,
    typeName: row.type_name,
    statusId: row.status_id,
    statusName: row.status_name,
    totalQuantity,
    borrowedQuantity,
    availableQuantity,
    statusLabel,
    isAvailable: !isMaintenance && availableQuantity > 0,
    description: row.description || `${row.name} thuoc nhom ${row.type_name}.`,
  };
}

function mapEmployee(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    username: row.username,
    email: row.email,
    role: Number(row.role),
    roleLabel: Number(row.role) === 0 ? "Quan tri vien" : "Nhan vien",
    employeeCode: row.employee_code,
  };
}

function normalizeDevicePayload(body = {}) {
  return {
    code: body.code?.trim(),
    name: body.name?.trim(),
    brand: body.brand?.trim() || null,
    model: body.model?.trim() || null,
    sku: body.sku?.trim() || null,
    description: body.description?.trim() || null,
    imageUrl: body.imageUrl?.trim() || null,
    productUrl: body.productUrl?.trim() || null,
    typeId: Number(body.typeId),
    statusId: Number(body.statusId),
    totalQuantity: Number(body.totalQuantity),
  };
}

async function validateDevicePayload(payload, deviceId = null) {
  if (!payload.code || !payload.name || !payload.typeId || !payload.statusId || !payload.totalQuantity) {
    throw new Error("Vui long nhap day du thong tin thiet bi.");
  }

  if (Number.isNaN(payload.typeId) || Number.isNaN(payload.statusId) || Number.isNaN(payload.totalQuantity)) {
    throw new Error("Du lieu thiet bi khong hop le.");
  }

  if (payload.totalQuantity < 1) {
    throw new Error("Tong so luong thiet bi phai lon hon 0.");
  }

  const typeRows = await query(`SELECT id FROM loaithietbi WHERE id = ? LIMIT 1`, [payload.typeId]);
  if (!typeRows.length) {
    throw new Error("Danh muc thiet bi khong ton tai.");
  }

  const statusRows = await query(`SELECT id FROM tinhtrangthietbi WHERE id = ? LIMIT 1`, [payload.statusId]);
  if (!statusRows.length) {
    throw new Error("Trang thai thiet bi khong ton tai.");
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
    throw new Error("Ma thiet bi hoac SKU da ton tai.");
  }
}

function mapLoanSlip(row) {
  const normalizedReturnCondition = normalizeText(row.return_condition || "");
  let status = row.status;

  if (normalizedReturnCondition === "hong hoc" || normalizedReturnCondition === "hong_hoc") {
    status = "hong_hoc";
  } else if (normalizedReturnCondition === "qua han" || normalizedReturnCondition === "qua_han") {
    status = "qua_han";
  }

  return {
    id: row.id,
    slipCode: `PM${String(row.id).padStart(3, "0")}`,
    borrowerId: row.borrower_id,
    borrowerName: row.borrower_name,
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    borrowDate: formatDateValue(row.borrow_date),
    dueDate: formatDateValue(row.due_date),
    status,
    note: row.note || "",
    deviceSummary: row.device_summary || "",
    totalItems: Number(row.total_items || 0),
  };
}

function mapFineSlip(row) {
  return {
    id: row.id,
    fineCode: `PP${String(row.id).padStart(3, "0")}`,
    loanSlipId: row.loan_slip_id,
    loanSlipCode: `PM${String(row.loan_slip_id).padStart(3, "0")}`,
    borrowerName: row.borrower_name,
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    issuedDate: formatDateValue(row.issued_date),
    fineType: row.fine_type,
    amount: Number(row.amount || 0),
    reason: row.reason || "",
    paymentStatus: row.payment_status,
    paymentDate: formatDateValue(row.payment_date),
    note: row.note || "",
    deviceSummary: row.device_summary || "",
  };
}

function getReturnConditionLabel(status) {
  if (status === "hong_hoc") return "Hong hoc";
  if (status === "qua_han") return "Qua han";
  return "Tot";
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

  throw new Error("Chi ho tro file CSV hoac XLS duoc xuat tu he thong.");
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
    throw new Error("Khong tim thay nhan vien nao de gan cho du lieu phuc hoi.");
  }

  return Number(rows[0].id);
}

async function ensureDeviceTypeId(typeName) {
  const trimmedName = String(typeName || "").trim();
  if (!trimmedName) {
    throw new Error("Khong xac dinh duoc danh muc thiet bi trong file phuc hoi.");
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
      totalQuantity: Math.max(1, parseNumberValue(pickRowValue(row, ["Tong so luong", "Total Quantity"])) || 1),
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
            tong_so_luong = ?,
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
          payload.totalQuantity,
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
            tong_so_luong,
            tinh_trang_id,
            ${deviceImageColumn}
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
          payload.totalQuantity,
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
    throw new Error("Vui long nhap ten nguoi muon.");
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
    throw new Error("Vui long nhap day du thong tin phieu muon.");
  }

  const [borrowerRows] = await connection.execute(`SELECT id FROM nguoimuon WHERE id = ? LIMIT 1`, [borrowerId]);
  if (!borrowerRows.length) {
    throw new Error("Nguoi muon khong ton tai.");
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

      if (status === "dang_muon") {
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
      return res.status(400).json({ message: "Vui long nhap tai khoan va mat khau." });
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
      return res.status(401).json({ message: "Tai khoan khong ton tai." });
    }

    const employee = rows[0];
    if (String(employee.password_admin) !== String(password)) {
      return res.status(401).json({ message: "Mat khau khong dung." });
    }

    return res.json({ message: "Dang nhap thanh cong.", user: mapEmployee(employee) });
  } catch (error) {
    return res.status(500).json({ message: "Khong the dang nhap.", error: error.message });
  }
}

app.get("/api/auth/login", handleLogin);
app.post("/api/auth/login", handleLogin);

app.post("/api/auth/forgot-password/request", async (req, res) => {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Vui long nhap email de nhan ma OTP." });
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
      return res.status(404).json({ message: "Email nay khong ton tai trong he thong." });
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
      message: "Da gui ma OTP qua email. Vui long kiem tra hop thu cua ban.",
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
      return res.status(400).json({ message: "Vui long nhap day du email, ma OTP va mat khau moi." });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Mat khau moi phai co it nhat 6 ky tu." });
    }

    const otpRecord = passwordResetOtps.get(email);
    if (!otpRecord) {
      return res.status(400).json({ message: "Ma OTP khong ton tai hoac da het han." });
    }

    if (otpRecord.expiresAt < Date.now()) {
      passwordResetOtps.delete(email);
      return res.status(400).json({ message: "Ma OTP da het han. Vui long yeu cau ma moi." });
    }

    if (otpRecord.otpHash !== hashOtp(otp)) {
      return res.status(400).json({ message: "Ma OTP khong dung." });
    }

    const rows = await query(`SELECT id FROM nhanvien WHERE id = ? AND LOWER(email) = ? LIMIT 1`, [
      otpRecord.employeeId,
      email,
    ]);

    if (!rows.length) {
      passwordResetOtps.delete(email);
      return res.status(404).json({ message: "Khong tim thay tai khoan can dat lai mat khau." });
    }

    await query(`UPDATE nhanvien SET password_admin = ? WHERE id = ?`, [newPassword, otpRecord.employeeId]);
    passwordResetOtps.delete(email);

    return res.json({ message: "Dat lai mat khau thanh cong. Ban co the dang nhap lai ngay bay gio." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the dat lai mat khau.", error: error.message });
  }
});

app.get("/api/employees", async (req, res) => {
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
    return res.status(500).json({ message: "Khong lay duoc danh sach nhan vien.", error: error.message });
  }
});

app.post("/api/employees", async (req, res) => {
  try {
    const fullName = req.body.fullName?.trim();
    const username = req.body.username?.trim();
    const password = req.body.password?.trim();
    const email = req.body.email?.trim();
    const role = Number(req.body.role);
    const employeeCode = normalizeEmployeeCode(req.body.employeeCode || "");

    if (!fullName || !username || !password || !email || !employeeCode || Number.isNaN(role)) {
      return res.status(400).json({ message: "Vui long nhap day du thong tin tai khoan." });
    }

    if (role !== 1) {
      return res.status(400).json({ message: "Chi duoc cap them tai khoan nhan vien." });
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
      return res.status(400).json({ message: "Username, email hoac ma nhan vien da ton tai." });
    }

    await query(
      `
        INSERT INTO nhanvien (${employeeNameColumn}, username, password_admin, email, role, ${employeeCodeColumn})
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      [fullName, username, password, email, role, employeeCode]
    );

    return res.status(201).json({ message: "Tao tai khoan thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the tao tai khoan.", error: error.message });
  }
});

app.get("/api/employees/:id", async (req, res) => {
  try {
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
      [Number(req.params.id)]
    );

    if (!rows.length) {
      return res.status(404).json({ message: "Khong tim thay nhan vien." });
    }

    return res.json(mapEmployee(rows[0]));
  } catch (error) {
    return res.status(500).json({ message: "Khong lay duoc thong tin tai khoan.", error: error.message });
  }
});

app.delete("/api/employees/:id", async (req, res) => {
  try {
    const employeeId = Number(req.params.id);

    if (Number.isNaN(employeeId)) {
      return res.status(400).json({ message: "ID nhan vien khong hop le." });
    }

    const rows = await query(`SELECT id, role FROM nhanvien WHERE id = ? LIMIT 1`, [employeeId]);

    if (!rows.length) {
      return res.status(404).json({ message: "Khong tim thay tai khoan can xoa." });
    }

    if (Number(rows[0].role) === 0) {
      return res.status(400).json({ message: "Khong duoc xoa tai khoan quan tri." });
    }

    const [loanRows, fineRows] = await Promise.all([
      query(`SELECT COUNT(*) AS total FROM phieumuon WHERE nhan_vien_id = ?`, [employeeId]).catch(() => [{ total: 0 }]),
      query(`SELECT COUNT(*) AS total FROM phieuphat WHERE nhan_vien_id = ?`, [employeeId]).catch(() => [{ total: 0 }]),
    ]);

    if (Number(loanRows[0]?.total || 0) > 0 || Number(fineRows[0]?.total || 0) > 0) {
      return res.status(400).json({
        message: "Tai khoan nay da duoc su dung trong phieu muon hoac phieu phat, khong the xoa.",
      });
    }

    await query(`DELETE FROM nhanvien WHERE id = ?`, [employeeId]);
    return res.json({ message: "Da xoa tai khoan nhan vien thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the xoa tai khoan.", error: error.message });
  }
});

app.put("/api/employees/:id/password", async (req, res) => {
  try {
    const employeeId = Number(req.params.id);
    const currentPassword = req.body.currentPassword?.trim();
    const newPassword = req.body.newPassword?.trim();

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Vui long nhap du mat khau hien tai va mat khau moi." });
    }

    const rows = await query(`SELECT id, password_admin FROM nhanvien WHERE id = ? LIMIT 1`, [employeeId]);

    if (!rows.length) {
      return res.status(404).json({ message: "Khong tim thay nhan vien." });
    }

    if (String(rows[0].password_admin) !== String(currentPassword)) {
      return res.status(400).json({ message: "Mat khau hien tai khong dung." });
    }

    await query(`UPDATE nhanvien SET password_admin = ? WHERE id = ?`, [newPassword, employeeId]);
    return res.json({ message: "Doi mat khau thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the doi mat khau.", error: error.message });
  }
});

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
    res.status(500).json({ message: "Khong lay duoc danh sach nguoi muon.", error: error.message });
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
    res.status(500).json({ message: "Khong lay duoc loai thiet bi", error: error.message });
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

    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Khong lay duoc trang thai thiet bi", error: error.message });
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
            SUM(CASE WHEN tb.tinh_trang_id = 1 AND GREATEST(tb.tong_so_luong - ${borrowedQuantitySql}, 0) > 0 THEN 1 ELSE 0 END) AS ready_devices,
            SUM(CASE WHEN tb.tinh_trang_id <> 1 OR GREATEST(tb.tong_so_luong - ${borrowedQuantitySql}, 0) = 0 THEN 1 ELSE 0 END) AS maintenance_devices
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
    res.status(500).json({ message: "Khong lay duoc du lieu dashboard.", error: error.message });
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
    res.status(500).json({ message: "Khong lay duoc danh sach thiet bi", error: error.message });
  }
});

app.post("/api/devices", async (req, res) => {
  try {
    const payload = normalizeDevicePayload(req.body);
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
          tong_so_luong,
          tinh_trang_id,
          ${deviceImageColumn}
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        payload.totalQuantity,
        payload.statusId,
        payload.imageUrl,
      ]
    );

    return res.status(201).json({ message: "Them thiet bi thanh cong.", id: result.insertId });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Khong the them thiet bi.", error: error.message });
  }
});

app.get("/api/devices/:id", async (req, res) => {
  try {
    const deviceId = Number(req.params.id);
    const rows = await query(buildDeviceSelectSql("WHERE tb.id = ?", "", "LIMIT 1"), [deviceId]);

    if (!rows.length) {
      return res.status(404).json({ message: "Khong tim thay thiet bi" });
    }

    const device = mapDevice(rows[0]);
    const relatedRows = await query(
      buildDeviceSelectSql("WHERE tb.loai_id = ? AND tb.id <> ?", "ORDER BY tb.id", "LIMIT 4"),
      [device.typeId, device.id]
    );

    return res.json({ ...device, relatedDevices: relatedRows.map(mapDevice) });
  } catch (error) {
    return res.status(500).json({ message: "Khong lay duoc chi tiet thiet bi", error: error.message });
  }
});

app.put("/api/devices/:id", async (req, res) => {
  try {
    const deviceId = Number(req.params.id);
    const payload = normalizeDevicePayload(req.body);

    const existingRows = await query(buildDeviceSelectSql("WHERE tb.id = ?", "", "LIMIT 1"), [deviceId]);
    if (!existingRows.length) {
      return res.status(404).json({ message: "Khong tim thay thiet bi." });
    }

    const existingDevice = mapDevice(existingRows[0]);
    const activeBorrowRows = await query(
      `
        SELECT COALESCE(SUM(ctpm.so_luong), 0) AS borrowed_quantity
        FROM chitietphieumuon ctpm
        INNER JOIN phieumuon pm ON pm.id = ctpm.phieu_muon_id
        WHERE ctpm.thiet_bi_id = ?
          AND pm.trang_thai = 'dang_muon'
      `,
      [deviceId]
    );
    const borrowedQuantity = Number(activeBorrowRows[0]?.borrowed_quantity || 0);

    if (payload.totalQuantity < borrowedQuantity) {
      return res.status(400).json({
        message: `Khong the giam tong so luong nho hon so dang muon (${borrowedQuantity}).`,
      });
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
          tong_so_luong = ?,
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
        payload.totalQuantity,
        payload.statusId,
        payload.imageUrl,
        deviceId,
      ]
    );

    return res.json({
      message:
        existingDevice.totalQuantity !== payload.totalQuantity
          ? "Cap nhat thiet bi thanh cong va da dieu chinh so luong ton kho."
          : "Cap nhat thiet bi thanh cong.",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Khong the cap nhat thiet bi.", error: error.message });
  }
});

app.delete("/api/devices/:id", async (req, res) => {
  try {
    const deviceId = Number(req.params.id);

    const rows = await query(`SELECT id, ten FROM thietbi WHERE id = ? LIMIT 1`, [deviceId]);
    if (!rows.length) {
      return res.status(404).json({ message: "Khong tim thay thiet bi." });
    }

    const activeBorrowRows = await query(
      `
        SELECT COALESCE(SUM(ctpm.so_luong), 0) AS borrowed_quantity
        FROM chitietphieumuon ctpm
        INNER JOIN phieumuon pm ON pm.id = ctpm.phieu_muon_id
        WHERE ctpm.thiet_bi_id = ?
          AND pm.trang_thai = 'dang_muon'
      `,
      [deviceId]
    );

    if (Number(activeBorrowRows[0]?.borrowed_quantity || 0) > 0) {
      return res.status(400).json({ message: "Thiet bi dang nam trong phieu muon, khong the xoa." });
    }

    const historyRows = await query(`SELECT phieu_muon_id FROM chitietphieumuon WHERE thiet_bi_id = ? LIMIT 1`, [deviceId]);
    if (historyRows.length) {
      return res.status(400).json({ message: "Thiet bi da co lich su phieu muon, khong the xoa." });
    }

    await query(`DELETE FROM thietbi WHERE id = ?`, [deviceId]);
    return res.json({ message: "Xoa thiet bi thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Khong the xoa thiet bi.", error: error.message });
  }
});

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
    res.status(500).json({ message: "Khong lay duoc danh sach phieu muon.", error: error.message });
  }
});

app.post("/api/loan-slips", async (req, res) => {
  const borrowerId = Number(req.body.borrowerId);
  const borrowerName = req.body.borrowerName?.trim() || "";
  const employeeId = Number(req.body.employeeId);
  const borrowDate = req.body.borrowDate?.trim();
  const dueDate = req.body.dueDate?.trim();
  const note = req.body.note?.trim() || null;
  const items = Array.isArray(req.body.items) ? req.body.items : [];

  if ((!borrowerId && !borrowerName) || !employeeId || !borrowDate || !dueDate || !items.length) {
    return res.status(400).json({ message: "Vui long nhap day du thong tin phieu muon." });
  }

  const normalizedItems = items
    .map((item) => ({ deviceId: Number(item.deviceId), quantity: Number(item.quantity), note: item.note?.trim() || null }))
    .filter((item) => item.deviceId && item.quantity > 0);

  if (!normalizedItems.length) {
    return res.status(400).json({ message: "Phieu muon can it nhat mot thiet bi hop le." });
  }

  const uniqueDeviceIds = [...new Set(normalizedItems.map((item) => item.deviceId))];
  if (uniqueDeviceIds.length !== normalizedItems.length) {
    return res.status(400).json({ message: "Moi thiet bi chi nen xuat hien mot lan trong phieu." });
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
        throw new Error("Co thiet bi khong ton tai trong he thong.");
      }

      if (!matchedDevice.isAvailable) {
        throw new Error(`Thiet bi "${matchedDevice.name}" hien khong san sang de muon.`);
      }

      if (item.quantity > matchedDevice.availableQuantity) {
        throw new Error(`So luong muon cua "${matchedDevice.name}" vuot qua so luong con trong (${matchedDevice.availableQuantity}).`);
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
        [slipResult.insertId, item.deviceId, item.quantity, matchedDevice.statusName || "Tot", item.note]
      );
    }

    await connection.commit();
    return res.status(201).json({ message: "Lap phieu muon thanh cong.", id: slipResult.insertId });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: error.message || "Khong the lap phieu muon.", error: error.message });
  } finally {
    connection.release();
  }
});

app.put("/api/loan-slips/:id/status", async (req, res) => {
  const slipId = Number(req.params.id);
  const employeeId = Number(req.body.employeeId);
  const status = req.body.status?.trim();
  const note = req.body.note?.trim() || null;
  const returnDate = req.body.returnDate?.trim() || new Date().toISOString().slice(0, 10);

  if (!slipId || !employeeId || !status) {
    return res.status(400).json({ message: "Vui long nhap day du thong tin cap nhat phiếu muon." });
  }

  if (!["da_tra", "hong_hoc", "qua_han"].includes(status)) {
    return res.status(400).json({ message: "Trang thai cap nhat khong hop le." });
  }

  const connection = await getConnection();

  try {
    await connection.beginTransaction();

    const [slipRows] = await connection.execute(
      `
        SELECT id, trang_thai
        FROM phieumuon
        WHERE id = ?
        LIMIT 1
      `,
      [slipId]
    );

    if (!slipRows.length) {
      throw new Error("Khong tim thay phieu muon.");
    }

    const currentStatus = slipRows[0].trang_thai;
    if (currentStatus === "da_tra") {
      throw new Error("Phieu muon nay da duoc xac nhan tra.");
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
    return res.json({
      message: status === "da_tra" ? "Cap nhat phiếu muon sang da tra thanh cong." : "Da ghi nhan phieu muon hong hoc.",
    });
  } catch (error) {
    await connection.rollback();
    return res.status(500).json({ message: error.message || "Khong the cap nhat phieu muon.", error: error.message });
  } finally {
    connection.release();
  }
});

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
    return res.status(500).json({ message: "Khong lay duoc danh sach phieu phat.", error: error.message });
  }
});

app.post("/api/fine-slips", async (req, res) => {
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
      return res.status(400).json({ message: "Vui long nhap day du thong tin phieu phat." });
    }

    const existingFineRows = await query(`SELECT id FROM phieuphat WHERE phieu_muon_id = ? LIMIT 1`, [loanSlipId]);
    if (existingFineRows.length) {
      return res.status(400).json({ message: "Phieu muon nay da duoc lap phieu phat." });
    }

    await query(
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

    return res.status(201).json({ message: "Tao phieu phat thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the tao phieu phat.", error: error.message });
  }
});

app.put("/api/fine-slips/:id", async (req, res) => {
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
      return res.status(400).json({ message: "Vui long nhap day du thong tin phieu phat." });
    }

    const existingRows = await query(`SELECT id FROM phieuphat WHERE id = ? LIMIT 1`, [fineId]);
    if (!existingRows.length) {
      return res.status(404).json({ message: "Khong tim thay phieu phat." });
    }

    const duplicateLoanSlipRows = await query(
      `SELECT id FROM phieuphat WHERE phieu_muon_id = ? AND id <> ? LIMIT 1`,
      [loanSlipId, fineId]
    );
    if (duplicateLoanSlipRows.length) {
      return res.status(400).json({ message: "Phieu muon nay da duoc lap phieu phat." });
    }

    await query(
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

    return res.json({ message: "Cap nhat phieu phat thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the cap nhat phieu phat.", error: error.message });
  }
});

app.delete("/api/fine-slips/:id", async (req, res) => {
  try {
    const fineId = Number(req.params.id);
    const existingRows = await query(`SELECT id FROM phieuphat WHERE id = ? LIMIT 1`, [fineId]);
    if (!existingRows.length) {
      return res.status(404).json({ message: "Khong tim thay phieu phat." });
    }

    await query(`DELETE FROM phieuphat WHERE id = ?`, [fineId]);
    return res.json({ message: "Xoa phieu phat thanh cong." });
  } catch (error) {
    return res.status(500).json({ message: "Khong the xoa phieu phat.", error: error.message });
  }
});

app.post("/api/restore", async (req, res) => {
  try {
    const target = req.body.target?.trim();
    const fileName = req.body.fileName?.trim();
    const content = req.body.content;

    if (!target || !fileName || typeof content !== "string") {
      return res.status(400).json({ message: "Vui long gui day du muc phuc hoi va noi dung file." });
    }

    const rows = parseRestoreRows(fileName, content);
    if (!rows.length) {
      return res.status(400).json({ message: "Khong doc duoc du lieu hop le tu file da chon." });
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
      return res.status(400).json({ message: "Loai du lieu phuc hoi khong hop le." });
    }

    if (!restoredCount) {
      return res.status(400).json({
        message: "Khong co dong nao duoc phuc hoi. Hay kiem tra dung file da xuat tu he thong va du lieu tham chieu hien co.",
      });
    }

    return res.json({ message: `Phuc hoi thanh cong ${restoredCount} dong du lieu cho muc ${target}.` });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Khong the phuc hoi du lieu.", error: error.message });
  }
});

Promise.all([resolveDeviceImageColumn(), resolveEmployeeColumns()]).finally(() => {
  app.listen(port, () => {
    console.log(`Backend is running on http://localhost:${port}`);
  });
});
