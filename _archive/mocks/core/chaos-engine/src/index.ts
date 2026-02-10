/**
 * Chaos Engineering Engine
 * Shared chaos injection utilities for all mock services
 *
 * Features:
 * - Latency injection with realistic distributions
 * - Error rate configuration
 * - Partial failure simulation
 * - Network issue simulation
 * - Deterministic chaos with seed
 */

export interface ChaosConfig {
  mode: 'off' | 'light' | 'moderate' | 'extreme';
  latency: {
    min: number;
    max: number;
    distribution?: 'uniform' | 'normal' | 'exponential';
  };
  errorRate: number;
  partialFailureEnabled: boolean;
  networkIssuesEnabled: boolean;
  seed?: string;
}

export interface ChaosResult {
  shouldFail: boolean;
  failureType?: 'timeout' | 'error' | 'partial' | 'network';
  delay: number;
  data?: any;
}

export class ChaosEngine {
  private config: ChaosConfig;
  private random: () => number;

  constructor(config: Partial<ChaosConfig> = {}) {
    this.config = {
      mode: config.mode || 'off',
      latency: config.latency || { min: 100, max: 500, distribution: 'uniform' },
      errorRate: config.errorRate || 0.01,
      partialFailureEnabled: config.partialFailureEnabled ?? true,
      networkIssuesEnabled: config.networkIssuesEnabled ?? true,
      seed: config.seed
    };

    // Seeded random for deterministic chaos
    if (this.config.seed) {
      this.random = this.seededRandom(this.config.seed);
    } else {
      this.random = Math.random;
    }
  }

  /**
   * Evaluate whether to inject chaos for this request
   */
  public evaluate(): ChaosResult {
    const delay = this.calculateDelay();
    const shouldFail = this.shouldInjectFailure();

    if (!shouldFail) {
      return { shouldFail: false, delay };
    }

    const failureType = this.selectFailureType();
    return { shouldFail: true, failureType, delay };
  }

  /**
   * Apply delay (returns promise that resolves after delay)
   */
  public async applyDelay(delay: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Update configuration at runtime
   */
  public updateConfig(updates: Partial<ChaosConfig>): void {
    this.config = { ...this.config, ...updates };
  }

  /**
   * Get current configuration
   */
  public getConfig(): ChaosConfig {
    return { ...this.config };
  }

  private calculateDelay(): number {
    const { min, max, distribution } = this.config.latency;

    switch (distribution) {
      case 'normal':
        return this.normalDistribution(min, max);
      case 'exponential':
        return this.exponentialDistribution(min, max);
      case 'uniform':
      default:
        return Math.floor(this.random() * (max - min + 1)) + min;
    }
  }

  private shouldInjectFailure(): boolean {
    if (this.config.mode === 'off') return false;

    let effectiveErrorRate = this.config.errorRate;

    switch (this.config.mode) {
      case 'light':
        effectiveErrorRate *= 0.5;
        break;
      case 'moderate':
        effectiveErrorRate *= 1;
        break;
      case 'extreme':
        effectiveErrorRate *= 3;
        break;
    }

    return this.random() < effectiveErrorRate;
  }

  private selectFailureType(): 'timeout' | 'error' | 'partial' | 'network' {
    const rand = this.random();
    const types: Array<'timeout' | 'error' | 'partial' | 'network'> = ['timeout', 'error'];

    if (this.config.partialFailureEnabled) {
      types.push('partial');
    }

    if (this.config.networkIssuesEnabled) {
      types.push('network');
    }

    const index = Math.floor(rand * types.length);
    return types[index];
  }

  // Normal distribution using Box-Muller transform
  private normalDistribution(min: number, max: number): number {
    const mean = (min + max) / 2;
    const stdDev = (max - min) / 6; // 99.7% within range

    const u1 = this.random();
    const u2 = this.random();
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);

    const value = mean + z * stdDev;
    return Math.max(min, Math.min(max, Math.floor(value)));
  }

  // Exponential distribution (more realistic for network latency)
  private exponentialDistribution(min: number, max: number): number {
    const lambda = 1 / ((max - min) / 3);
    const value = min + (-Math.log(1 - this.random()) / lambda);
    return Math.min(max, Math.floor(value));
  }

  // Seeded random number generator (LCG algorithm)
  private seededRandom(seed: string): () => number {
    let state = this.hashCode(seed);

    return () => {
      state = (state * 1103515245 + 12345) & 0x7fffffff;
      return state / 0x7fffffff;
    };
  }

  private hashCode(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }
}

/**
 * Chaos middleware for Express
 */
export function chaosMiddleware(engine: ChaosEngine) {
  return async (req: any, res: any, next: any) => {
    const result = engine.evaluate();

    // Apply delay
    await engine.applyDelay(result.delay);

    // Inject failure if needed
    if (result.shouldFail) {
      switch (result.failureType) {
        case 'timeout':
          // Don't respond, let client timeout
          return;
        case 'error':
          return res.status(500).json({
            error: 'CHAOS_INJECTED_ERROR',
            message: 'Simulated server error',
            timestamp: new Date().toISOString()
          });
        case 'network':
          // Destroy connection
          req.socket.destroy();
          return;
        case 'partial':
          // Mark for partial response (handled by service)
          req.chaosPartial = true;
          break;
      }
    }

    next();
  };
}

export default ChaosEngine;
