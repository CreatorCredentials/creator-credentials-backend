const JWT_FORMAT = 'jwt';

/** `?format=jwt`, or an Accept header naming the JWT media type, asks for the compact JWS. */
export function wantsJwt(
  format: string | undefined,
  accept: string | undefined,
  jwtMediaType: string,
): boolean {
  return format === JWT_FORMAT || (accept ?? '').includes(jwtMediaType);
}
