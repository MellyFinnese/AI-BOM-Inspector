export function calculateTotal(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0);
}

export function formatName(first: string, last: string): string {
  return `${first} ${last}`;
}
