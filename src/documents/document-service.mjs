import { BankError, iso, opaqueId, requireOpaque, requireText } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

function pdfEscape(value) { return String(value).replaceAll("\\", "\\\\").replaceAll("(", "\\(").replaceAll(")", "\\)").replaceAll(/[^\x20-\x7e]/g, "?"); }

export function renderReceiptPdf(lines) {
  const content = ["BT", "/F1 11 Tf", "50 790 Td"];
  for (const [index, line] of lines.entries()) {
    if (index > 0) content.push("0 -18 Td");
    content.push(`(${pdfEscape(line)}) Tj`);
  }
  content.push("ET");
  const stream = `${content.join("\n")}\n`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}endstream`,
  ];
  let output = "%PDF-1.4\n"; const offsets = [0];
  objects.forEach((object, index) => { offsets.push(Buffer.byteLength(output)); output += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(output); output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i++) output += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  output += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(output, "ascii");
}

export class DocumentService {
  constructor({ repository, now = () => new Date() } = {}) { this.repository = repository; this.now = now; }

  createReceiptInState(state, { ownerReference, operationReference, type, title, fields, correlationId }) {
    requireOpaque(ownerReference); requireOpaque(operationReference); requireText(type, "INVALID_DOCUMENT_TYPE", 48); requireText(title, "INVALID_DOCUMENT_TITLE", 100);
    const documentReference = opaqueId("doc");
    const lines = ["BNI Home Banking", title, ...fields.map(([label, value]) => `${label}: ${value}`)];
    const bytes = renderReceiptPdf(lines);
    const document = { documentReference, ownerReference, operationReference, type, title, mimeType: "application/pdf", sizeBytes: bytes.length, contentBase64: bytes.toString("base64"), createdAt: iso(this.now()) };
    state.documents[documentReference] = document;
    addAudit(state, { type: "DOCUMENT_CREATED", subjectReference: documentReference, actorReference: ownerReference, outcome: "SUCCESS", correlationId, details: { documentType: type, sizeBytes: bytes.length } }, this.now);
    addOutbox(state, { type: "DOCUMENT_AVAILABLE", aggregateReference: ownerReference, payload: { documentReference, title }, correlationId }, this.now);
    return { documentReference, title, mimeType: document.mimeType, sizeBytes: document.sizeBytes, createdAt: document.createdAt };
  }

  list(ownerReference) {
    const state = this.repository.snapshot();
    return Object.values(state.documents).filter((doc) => doc.ownerReference === ownerReference).map((doc) => { const metadata = { ...doc }; delete metadata.contentBase64; return metadata; }).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  get(documentReference, ownerReference) {
    const document = this.repository.snapshot().documents[requireOpaque(documentReference)];
    if (!document || document.ownerReference !== ownerReference) throw new BankError("DOCUMENT_NOT_FOUND", 404);
    return { ...document, bytes: Buffer.from(document.contentBase64, "base64"), contentBase64: undefined };
  }
}
