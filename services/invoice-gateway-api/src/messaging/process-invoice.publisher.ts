import pino from 'pino';
import { ProcessInvoiceCommand } from '@eracun/contracts';
import { RabbitMQClient } from './rabbitmq-client';

export interface ProcessInvoiceCommandPublisher {
  publish(command: ProcessInvoiceCommand): Promise<void>;
}

interface PublisherOptions {
  queueName?: string;
  client?: RabbitMQClient;
}

export class RabbitMQProcessInvoicePublisher implements ProcessInvoiceCommandPublisher {
  private readonly client: RabbitMQClient;
  private readonly queueName: string;
  private readonly logger = pino({ name: 'process-invoice-publisher' });
  private connecting: Promise<void> | null = null;
  private connected = false;

  constructor(options: PublisherOptions = {}) {
    this.queueName =
      options.queueName || process.env.PROCESS_INVOICE_QUEUE || 'process-invoice';
    this.client = options.client || new RabbitMQClient(process.env.RABBITMQ_URL);
  }

  async publish(command: ProcessInvoiceCommand): Promise<void> {
    await this.ensureConnected();

    await this.client.publishToQueue(this.queueName, command, {
      correlationId: command.correlationId,
      messageId: command.payload.sourceId,
      headers: {
        'command-type': command.type,
        'idempotency-key': command.payload.metadata?.idempotencyKey || '',
      },
    });

    this.logger.info(
      {
        invoiceId: command.payload.sourceId,
        correlationId: command.correlationId,
      },
      'ProcessInvoiceCommand published'
    );
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected) {
      return;
    }

    if (!this.connecting) {
      this.connecting = this.client.connect().then(() => {
        this.connected = true;
        this.logger.info({ queue: this.queueName }, 'Connected to RabbitMQ for publishing');
      });
    }

    await this.connecting;
  }
}
