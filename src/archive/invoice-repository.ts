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
  userId: string,
  status: string,
  jir?: string,
  finaResponse?: Record<string, unknown>
): Promise<void> {
  await query(
    `UPDATE invoices
     SET status = $1, jir = $2, fina_response = $3, updated_at = NOW(),
         submitted_at = CASE WHEN $1 = 'completed' THEN NOW() ELSE submitted_at END
     WHERE id = $4 AND user_id = $5`,
    [status, jir || null, finaResponse ? JSON.stringify(finaResponse) : null, id, userId]
  );
}

export async function getInvoiceById(id: string, userId: string): Promise<Invoice | null> {
  const result = await query('SELECT * FROM invoices WHERE id = $1 AND user_id = $2', [id, userId]);
  return result.rows[0] || null;
}

export async function getInvoicesByOIB(
  oib: string,
  userId: string,
  limit = 50,
  offset = 0
): Promise<Invoice[]> {
  const result = await query(
    'SELECT * FROM invoices WHERE oib = $1 AND user_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4',
    [oib, userId, limit, offset]
  );
  return result.rows;
}

export async function updateStatus(
  id: string,
  userId: string,
  status: 'pending' | 'processing' | 'completed' | 'failed'
): Promise<void> {
  await query(
    'UPDATE invoices SET status = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
    [status, id, userId]
  );
}
