import {
  IsIn,
  IsMimeType,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { CertificateConfigOptions } from '../certificates.util';

export class CreateKeyAndCertificateDto {
  subject: string;
  countryName: string;
  stateOrProvinceName: string;
  localityName: string;
  organizationName: string;
  organizationalUnitName: string;
  commonName: string;
  crlDistributionPoints: string;
  issuerURI1: string;
  issuerURI2: string;
  subjectURI1: string;
  subjectURI2: string;
}
