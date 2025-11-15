import { DeadLetterFilter } from '../generated/admin_portal';

export function buildDeadLetterFilters(rawQuery: Record<string, unknown>): DeadLetterFilter[] {
  return Object.entries(rawQuery)
    .filter(([key, value]) => typeof value === 'string' && key !== 'page' && key !== 'pageSize')
    .map(([key, value]) => ({ key, value: value as string }));
}
