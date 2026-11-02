/** `issuer` of a credential object: a DID string, or an object whose `id` is the DID. */
export function issuerDidOf(
  credential: Record<string, unknown>,
): string | null {
  const issuer = credential.issuer;
  if (typeof issuer === 'string') {
    return issuer;
  }
  if (issuer !== null && typeof issuer === 'object') {
    const id = (issuer as Record<string, unknown>).id;
    return typeof id === 'string' ? id : null;
  }
  return null;
}
