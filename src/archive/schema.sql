CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  oib VARCHAR(11) NOT NULL,
  invoice_number VARCHAR(100) NOT NULL,
  original_xml TEXT NOT NULL,
  signed_xml TEXT NOT NULL,
  jir VARCHAR(100),
  fina_response JSONB,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  submitted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT valid_oib CHECK (length(oib) = 11),
  CONSTRAINT valid_status CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_invoices_oib ON invoices(oib);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_created_at ON invoices(created_at);
