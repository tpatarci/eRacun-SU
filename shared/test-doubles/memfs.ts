import path from 'node:path';

type JsonInput = Record<string, string | Buffer>;

class InMemoryVolume {
  private files = new Map<string, Buffer>();

  fromJSON(tree: JsonInput): void {
    this.reset();
    for (const [filePath, value] of Object.entries(tree)) {
      const normalized = this.normalizePath(filePath);
      const buffer = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, 'utf8');
      this.files.set(normalized, buffer);
    }
  }

  reset(): void {
    this.files.clear();
  }

  readFile(filePath: string): Buffer {
    const normalized = this.normalizePath(filePath);
    const contents = this.files.get(normalized);
    if (!contents) {
      const error = new Error(`ENOENT: no such file or directory, open '${normalized}'`);
      (error as NodeJS.ErrnoException).code = 'ENOENT';
      throw error;
    }
    return Buffer.from(contents);
  }

  writeFile(filePath: string, data: Buffer | string): void {
    const normalized = this.normalizePath(filePath);
    const buffer = Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(data, 'utf8');
    this.files.set(normalized, buffer);
  }

  private normalizePath(filePath: string): string {
    if (!filePath) {
      return '/';
    }
    const replaced = filePath.replace(/\\/g, '/');
    const normalized = path.posix.normalize(replaced.startsWith('/') ? replaced : `/${replaced}`);
    return normalized;
  }
}

const volume = new InMemoryVolume();

export const vol = {
  fromJSON: (tree: JsonInput): void => volume.fromJSON(tree),
  reset: (): void => volume.reset(),
};

export const fs = {
  promises: {
    async readFile(filePath: string, encoding?: BufferEncoding): Promise<Buffer | string> {
      const buffer = volume.readFile(filePath);
      if (encoding) {
        return buffer.toString(encoding);
      }
      return buffer;
    },
    async writeFile(filePath: string, data: Buffer | string): Promise<void> {
      volume.writeFile(filePath, data);
    },
  },
};

export default {
  vol,
  fs,
};
