import { Container } from 'inversify';
import { SERVICE_TYPES } from './types/di';
import {
  InvoiceRepository,
  PostgresInvoiceRepository,
} from './repositories/invoice.repository';
import {
  ProcessInvoiceCommandPublisher,
  RabbitMQProcessInvoicePublisher,
} from './messaging/process-invoice.publisher';

export function registerInvoiceGatewayDependencies(container: Container): void {
  if (!container.isBound(SERVICE_TYPES.InvoiceRepository)) {
    const repository: InvoiceRepository = new PostgresInvoiceRepository();
    container
      .bind<InvoiceRepository>(SERVICE_TYPES.InvoiceRepository)
      .toConstantValue(repository);
  }

  if (!container.isBound(SERVICE_TYPES.ProcessInvoicePublisher)) {
    const publisher: ProcessInvoiceCommandPublisher =
      new RabbitMQProcessInvoicePublisher();
    container
      .bind<ProcessInvoiceCommandPublisher>(SERVICE_TYPES.ProcessInvoicePublisher)
      .toConstantValue(publisher);
  }
}
