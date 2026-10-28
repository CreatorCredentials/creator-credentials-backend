import { instanceToPlain } from 'class-transformer';
import { ClerkRole, User } from './user.entity';

const SECRET_FIELDS = [
  'certificatePrivateKey',
  'certificate509Buffer',
  'nonce',
  'domainRecord',
  'didWebWellKnown',
];

function buildUser(): User {
  return Object.assign(new User(), {
    id: 1,
    clerkId: 'clerk_1',
    clerkRole: ClerkRole.Creator,
    name: 'Alice',
    didKey: 'did:key:zAlice',
    nonce: 'nonce',
    domainRecord: 'cc-verification=record',
    didWebWellKnown: {
      '@context': [],
      id: '',
      value: '',
      verificationMethod: [],
      authentication: [],
    },
    certificate509Buffer: Buffer.from('certificate'),
    certificatePrivateKey: Buffer.from('private key'),
  });
}

describe('User serialization', () => {
  it.each(SECRET_FIELDS)('never exposes %s', (field) => {
    expect(instanceToPlain(buildUser())).not.toHaveProperty(field);
  });

  it('keeps the public profile fields', () => {
    expect(instanceToPlain(buildUser())).toMatchObject({
      id: 1,
      name: 'Alice',
      didKey: 'did:key:zAlice',
      clerkRole: ClerkRole.Creator,
    });
  });
});
