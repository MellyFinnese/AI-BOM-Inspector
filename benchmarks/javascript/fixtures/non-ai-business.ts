export function calculateInvoice(total: number, tax: number) {
  const subtotal = total * (1 + tax);
  return Math.round(subtotal * 100) / 100;
}

export function normalizeCustomer(name: string) {
  return name.trim().toLowerCase();
}
