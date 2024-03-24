import {
  DidWebCredential,
  DomainCredential,
  EmailCredential,
  MembershipCredential,
  VerifiedCredentialsUnion,
  WalletCredential,
} from 'src/shared/typings/Credentials';
import { Credential } from './credential.entity';
import { CredentialType } from 'src/shared/typings/CredentialType';
import { NotFoundException } from '@nestjs/common';

export function formatCredentialForUnion(
  credential: Credential,
): VerifiedCredentialsUnion {
  switch (credential.credentialType) {
    case CredentialType.EMail:
      return formatEmailCredential(credential);
    case CredentialType.DidWeb:
      return formatDidWebCredential(credential);
    case CredentialType.Wallet:
      return formatWalletCredential(credential);
    case CredentialType.Domain:
      return formatDomainCredential(credential);
    case CredentialType.Member:
      return formatMemberCredential(credential);
    default:
      throw new NotFoundException(
        'CredentialType is not defined properly for credential.',
      );
  }
}

export function formatEmailCredential(credential: Credential): EmailCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.EMail,
    data: {
      address: credential.email || 'wrong',
      companyName: 'Creator Credentials B.V.',
      requirements: 'Info about requirements',
      credentialObject: credential,
    },
  };
}

export function formatWalletCredential(
  credential: Credential,
): WalletCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Wallet,
    data: {
      address: credential.credentialObject.walletAddress || 'wrong',
      companyName: 'Creator Credentials B.V.',
      requirements: 'Info about requirements',
      credentialObject: credential,
    },
  };
}

export function formatDomainCredential(
  credential: Credential,
): DomainCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Domain,
    data: {
      domain: credential.email || 'wrong',
      companyName: 'Creator Credentials B.V.',
      requirements: 'Info about requirements',
      credentialObject: credential,
    },
  };
}

export function formatDidWebCredential(
  credential: Credential,
): DidWebCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.DidWeb,
    data: {
      domain: credential.email || 'wrong',
      companyName: 'Creator Credentials B.V.',
      requirements: 'Info about requirements',
      credentialObject: credential,
    },
  };
}

export function formatMemberCredential(
  credential: Credential,
): MembershipCredential {
  return {
    id: credential.id.toString(),
    status: credential.credentialStatus,
    type: CredentialType.Member,
    data: {
      validity: credential.value || 'wrong',
      companyName: 'Creator Credentials B.V.',
      requirements: 'Info about requirements',
      credentialObject: credential,
    },
  };
}
