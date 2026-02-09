import { logger } from '../../src/shared/logger';

describe('Logger', () => {
  it('should output JSON with msg, level, and custom fields', () => {
    const output: unknown[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: unknown) => {
      output.push(chunk);
      return true;
    }) as typeof process.stdout.write;

    logger.info({ invoice: '123' }, 'test message');

    process.stdout.write = originalWrite;

    const logged = output[0] as string;
    // Pino outputs numeric level codes (30 = info)
    expect(logged).toContain('"msg":"test message"');
    expect(logged).toContain('"invoice":"123"');
    expect(logged).toContain('"level":30');
  });
});
