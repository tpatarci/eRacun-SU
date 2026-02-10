import { query } from '../shared/db.js';
import type { Invoice } from '../shared/types.js';

export async function createInvoice(data: {
  oib: string;
  invoiceNumber: string;
  originalXml: string;
  signedXml: string;
  userId: string;
}): Promise<Invoice> {
  const result = await query(
    `INSERT INTO invoices (oib, invoice_number, original_xml, signed_xml, user_id)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [data.oib, data.invoiceNumber, data.originalXml, data.signedXml, data.userId]
  );
  return result.rows[0];
}

export async function updateInvoiceStatus(
  id: string,
  status: string,
  jir?: string,
  finaResponse?: Record<string, unknown>
): Promise<void> {
  await query(
    `UPDATE invoices
     SET status = $1, jir = $2, fina_response = $3, updated_at = NOW(),
         submitted_at = CASE WHEN $1 = 'completed' THEN NOW() ELSE submitted_at END
     WHERE id = $4`,
    [status, jir || null, finaResponse ? JSON.stringify(finaResponse) : null, id]
  );
}

export async function getInvoiceById(id: string): Promise<Invoice | null> {
  const result = await query('SELECT * FROM invoices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

export async function getInvoicesByOIB(
  oib: string,
  limit = 50,
  offset = 0
): Promise<Invoice[]> {
  const result = await query(
    'SELECT * FROM invoices WHERE oib = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
    [oib, limit, offset]
  );
  return result.rows;
}

export async function updateStatus(
  id: string,
  status: 'pending' | 'processing' | 'completed' | 'failed'
): Promise<void> {
  await query(
    'UPDATE invoices SET status = $1, updated_at = NOW() WHERE id = $2',
    [status, id]
  );
}
