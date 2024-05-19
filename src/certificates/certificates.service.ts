import { Injectable } from '@nestjs/common';
import { CreateKeyAndCertificateDto } from './dto/create-key-and-certificate-dto';
import { exec } from 'child_process';
import {
  CertificateConfigOptions,
  getCnfCertificateConfig,
} from './certificates.util';
import { readFile } from 'fs/promises';

const CERTIFICATE_GENERATION_DIRECTORY = '../certificates/users';

@Injectable()
export class CertificatesService {
  constructor() {}

  private async createPrivateKeyAndIssueCertificate(
    options: CertificateConfigOptions,
  ): Promise<{
    certificateBuffer: Buffer;
    privateKeyBuffer: Buffer;
  }> {
    const { subject, directory } = options;

    const cnfFileContent = getCnfCertificateConfig(options);
    const certificatePath = `${directory}/${subject}`;

    console.log('createPrivateKeyAndIssueCertificate 1');
    const clearCommand = `mkdir -p ${directory}/${subject} && rm -rf ${certificatePath}`;
    await new Promise((resolve, reject) => {
      exec(clearCommand, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          reject(error);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          console.error(`stdout: ${stdout}`);
          console.error(`error: ${error}`);
          reject(error);
          return;
        }
        resolve(stdout);
      });
    });

    const commandToCreateConfig = `mkdir -p ${certificatePath} &&
        touch ${certificatePath}/config.cnf &&
        echo "${cnfFileContent}" > ${certificatePath}/config.cnf`;

    console.log('createPrivateKeyAndIssueCertificate 2');

    await new Promise((resolve, reject) => {
      exec(commandToCreateConfig, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          reject(error);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          console.error(`stdout: ${stdout}`);
          console.error(`error: ${error}`);
          reject(error);
          return;
        }
        resolve(stdout);
      });
    });

    console.log('createPrivateKeyAndIssueCertificate 3');

    const scriptPath =
      'src/certificates/create-cert-sh-script/create-self-signed.sh';
    const command = `${scriptPath} ${CERTIFICATE_GENERATION_DIRECTORY} ${subject} ${365}`;
    await new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.log('createPrivateKeyAndIssueCertificate 3 error happened');

          console.error(`Error: ${error.message}`);
          console.log(error);

          reject(error);
          return;
        }
        if (stderr) {
          if (!error) {
            resolve(stdout);
            return;
          }
          console.error(`stderr: ${stderr}`);
          console.error(`stdout: ${stdout}`);
          console.error(`error: ${error}`);
          reject(error);
          return;
        }
        resolve(stdout);
      });
    });

    const [certificateBuffer, privateKeyBuffer] = await Promise.all([
      readFile(`./${certificatePath}/certs/cert.pem`),
      readFile(`./${certificatePath}/private/key.secret.pem`),
    ]);

    console.log('createPrivateKeyAndIssueCertificate 4');

    await new Promise((resolve, reject) => {
      exec(`rm -rf ${certificatePath}`, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          reject(error);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          console.error(`stdout: ${stdout}`);
          console.error(`error: ${error}`);
          reject(error);
          return;
        }
        resolve(stdout);
      });
    });

    return {
      certificateBuffer,
      privateKeyBuffer,
    };
  }

  createKeyAndCertificate(
    createKeyAndCertificateDto: CreateKeyAndCertificateDto,
  ): Promise<{
    certificateBuffer: Buffer;
    privateKeyBuffer: Buffer;
  }> {
    return this.createPrivateKeyAndIssueCertificate({
      directory: CERTIFICATE_GENERATION_DIRECTORY,
      ...createKeyAndCertificateDto,
    });
  }
}
