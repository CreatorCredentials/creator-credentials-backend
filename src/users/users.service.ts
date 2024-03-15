import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './user.entity';
import { users } from '@clerk/clerk-sdk-node';
import { CredentialsService } from 'src/credentials/credentials.service';
import { JustNonceDto } from './dto/just-nonce.dto';
import {
  toBuffer,
  hashPersonalMessage,
  fromRpcSig,
  ecrecover,
  publicToAddress,
  bufferToHex,
} from 'ethereumjs-util';
import { ConfigService } from '@nestjs/config';
import { resolveTxt } from 'dns';
import {
  CreateTxtRecordForDomainResponse,
  CreateWellKnownForDidWebResponse,
} from './users.types';
import { Cron, CronExpression } from '@nestjs/schedule';
import { domainVerificationPrefix } from 'src/credentials/credentials.constants';
import { HttpService } from '@nestjs/axios';
import * as https from 'https';
import { map } from 'rxjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private credentialsService: CredentialsService,
    private configService: ConfigService,
    private httpService: HttpService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const newUser = new User();
    newUser.clerkId = createUserDto.clerkId;
    newUser.clerkRole = createUserDto.clerkRole;

    const nonce = this.generateNonce();
    newUser.nonce = nonce;

    const user = await this.userRepository.save(newUser, { reload: true });
    const userFromClerk = await users.getUser(createUserDto.clerkId);

    const email = userFromClerk.emailAddresses[0].emailAddress;

    await this.credentialsService.createEmailCredential(
      { email, did: email },
      user,
    );
    return user;
  }

  async getByClerkId(clerkId: string): Promise<User> {
    return this.userRepository.findOne({ where: { clerkId } });
  }
  private generateNonce() {
    return Math.floor(Math.random() * 1000000000).toString();
  }

  async updateNonce(clerkId: string): Promise<User> {
    const user = await this.userRepository.findOneBy({ clerkId });
    if (!user) {
      throw new NotFoundException();
    }
    user.nonce = this.generateNonce();
    user.nonceChangedAt = new Date();
    return this.userRepository.save(user);
  }

  async provideNonceForUser(clerkId: string): Promise<JustNonceDto> {
    const user = await this.userRepository.findOneBy({ clerkId });

    if (!user) {
      throw new NotFoundException();
    }

    const updatedUser = await this.updateNonce(user.clerkId);

    console.log(updatedUser);
    return { nonce: updatedUser.nonce };
  }

  async verifySignatureAndConnectAddress(
    clerkId: string,
    address: string,
    signedMessage: string,
  ): Promise<any> {
    const userByAddress = await this.userRepository.findOneBy({
      publicAddress: address,
    });
    if (userByAddress) {
      throw new NotFoundException(
        'Public address already assigned to another user.',
      );
    }

    const user = await this.getByClerkId(clerkId);

    this.checkSignatureAndThrow(user.nonce, address, signedMessage);

    user.publicAddress = address;
    const updatedUser = await this.userRepository.save(user, { reload: true });
    await this.credentialsService.createWalletCredential(
      { publicAddress: address, did: address },
      updatedUser,
    );

    return updatedUser;
  }

  private checkSignatureAndThrow(
    nonce: string,
    address: string,
    signedMessage: string,
  ) {
    const termsAndConditionsUrl = this.configService.getOrThrow(
      'TERMS_AND_CONDITIONS_URL',
    );
    const message = `Welcome to Creator Credentials app!\n\nClick to sign-in and accept the Terms of Service (${termsAndConditionsUrl}).\n\nThis request will not trigger a blockchain transaction or cost any gas fees.\n\nYour wallet address:\n${address}\n\nNonce:\n${nonce}`;

    // Check if signature is valid
    const msgBuffer = toBuffer(bufferToHex(Buffer.from(message)));
    const msgHash = hashPersonalMessage(msgBuffer);
    const signatureParams = fromRpcSig(signedMessage);
    const publicKey = ecrecover(
      msgHash,
      signatureParams.v,
      signatureParams.r,
      signatureParams.s,
    );
    const addressBuffer = publicToAddress(publicKey);
    const addressHashed = bufferToHex(addressBuffer);
    // Check if address matches
    if (addressHashed.toLowerCase() !== address.toLowerCase()) {
      throw new UnauthorizedException();
    }
  }

  async disconnectAddress(clerkId: string) {
    const user = await this.userRepository.findOneBy({ clerkId });

    user.publicAddress = null;
    const updatedUser = await this.userRepository.save(user, { reload: true });

    await this.credentialsService.removeWalletCredential(updatedUser);
    return updatedUser;
  }

  private generateDomainRecord() {
    return `${domainVerificationPrefix}0x${this.makeid(
      UsersService.recordLength,
    )}`;
  }

  private static readonly recordLength = 126;
  private makeid(length: number) {
    let result = '';
    const characters =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
      counter += 1;
    }
    return result;
  }

  async receiveAndUpdateDomainRecord(
    user: User,
    domain: string,
  ): Promise<CreateTxtRecordForDomainResponse> {
    if (user.domain && domain === user.domain && user.domainRecord) {
      return {
        txtRecord: user.domainRecord,
      };
    }
    await this.credentialsService.removeDomainCredential(user);

    user.domainRecord = this.generateDomainRecord();
    user.domain = domain;
    user.domainPendingVerifcation = false;
    user.domainRecordChangedAt = new Date();

    const updatedUser = await this.userRepository.save(user, { reload: true });

    return {
      txtRecord: updatedUser.domainRecord,
    };
  }

  async confirmDomainRecordCreated(user: User) {
    await this.credentialsService.removeDomainCredential(user);

    user.domainPendingVerifcation = true;
    await this.userRepository.save(user, { reload: true });

    await this.credentialsService.createPendingDomainCredential(
      { did: user.domain, domain: user.domain },
      user,
    );

    this.verifyDomainRecordAndConnect(user);
  }

  async resolveTxtOnDomain(domain: string): Promise<string[][]> {
    return new Promise((resolve, reject) => {
      resolveTxt(domain, (err, addresses) => {
        if (err) {
          reject(err);
        }
        resolve(addresses);
      });
    });
  }

  @Cron(CronExpression.EVERY_10_SECONDS)
  async checkUserDomains() {
    const users = await this.userRepository.find({
      where: { domainPendingVerifcation: true },
    });
    users.forEach((user) => this.verifyDomainRecordAndConnect(user));
  }

  private async verifyDomainRecordAndConnect(user: User) {
    const records = await this.resolveTxtOnDomain(user.domain);

    const creatorCredentialsMessagesFromRecords = records.filter((record) =>
      record.some((value) => value.includes(domainVerificationPrefix)),
    );

    // const valueToVerify = creatorCredentialsMessagesFromRecords[0][0];
    console.log(
      'verifyRecordAndConnectDomain: ',
      creatorCredentialsMessagesFromRecords,
    );
    console.log('verifyRecordAndConnectDomain: ', user.domainRecord);
    const doesValuePresented = creatorCredentialsMessagesFromRecords.some(
      (record) => record.some((value) => value === user.domainRecord),
    );
    // if (valueToVerify && valueToVerify === user.domainRecord) {
    if (doesValuePresented) {
      await this.credentialsService.createDomainCredential(
        { did: user.domain, domain: user.domain },
        user,
      );
      await this.userRepository.update(
        { clerkId: user.clerkId },
        { domainPendingVerifcation: false },
      );
    }
  }

  async disconnectDomain(clerkId: string) {
    const user = await this.userRepository.findOneBy({ clerkId });

    user.domain = null;
    user.domainRecord = null;
    user.domainPendingVerifcation = false;
    user.domainRecordChangedAt = new Date();
    const updatedUser = await this.userRepository.save(user, { reload: true });

    await this.credentialsService.removeDomainCredential(updatedUser);
    return updatedUser;
  }

  async receiveAndUpdateDidWebWellKnown(
    user: User,
    didWeb: string,
  ): Promise<CreateWellKnownForDidWebResponse> {
    if (user.didWeb && didWeb === user.didWeb && user.didWebWellKnown) {
      return {
        wellKnownJsonString: `// ${user.didWebWellKnownChangedAt.toUTCString()}
      // https://www.${didWeb}/.well-known/did.json
        ${JSON.stringify(user.didWebWellKnown, null, 2)}
      `,
      };
    }

    await this.credentialsService.removeDidWebCredential(user);
    user.didWeb = didWeb;
    user.didWebWellKnown = this.generateWellKnownForDidWeb(didWeb);
    user.didWebPendingVerifcation = false;
    user.didWebWellKnownChangedAt = new Date();

    const updatedUser = await this.userRepository.save(user, { reload: true });

    return {
      wellKnownJsonString: JSON.stringify(updatedUser.didWebWellKnown, null, 2),
    };
  }

  private generateWellKnownForDidWeb(didWeb: string) {
    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
      id: `did:web:${didWeb}`,
      value: didWeb,
      verificationMethod: [
        {
          id: `did:web:${didWeb}#key-0`,
          type: 'JsonWebKey2020',
          controller: `did:web:${didWeb}`,
          publicKeyJwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: this.makeid(32),
          },
        },
      ],
      authentication: ['did:web:creatorcredentials.dev#key-0'],
    };
  }

  async confirmDidWebWellKnownCreated(user: User) {
    user.didWebPendingVerifcation = true;
    await this.userRepository.save(user, { reload: true });
    await this.credentialsService.removeDidWebCredential(user);

    await this.credentialsService.createPendingDidWebCredential(
      { did: user.domain, didWeb: user.didWeb },
      user,
    );

    this.verifyDidWebWellKnownAndConnect(user);
  }

  @Cron(CronExpression.EVERY_10_SECONDS)
  async checkUsersDidWeb() {
    try {
      const users = await this.userRepository.find({
        where: { didWebPendingVerifcation: true },
      });
      users.forEach((user) => this.verifyDidWebWellKnownAndConnect(user));
    } catch (error) {
      console.log(error);
    }
  }

  private async getDidWebWellKnowOfUser(user: User): Promise<any> {
    const didWebFromServer = await this.httpService
      .get(`https://${user.didWeb}/.well-known/did.json`, {
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
      })
      .pipe(map((response) => response.data))
      .toPromise();

    return didWebFromServer;
  }

  private async verifyDidWebWellKnownAndConnect(user: User) {
    const wellKnown = await this.getDidWebWellKnowOfUser(user);
    const toCompare = user.didWebWellKnown;
    const doesWellKnowMatch =
      wellKnown.verificationMethod[0].publicKeyJwk.x ===
      toCompare.verificationMethod[0].publicKeyJwk.x;

    console.log(wellKnown);

    console.log(toCompare);

    if (doesWellKnowMatch) {
      await this.credentialsService.createDidWebCredential(
        { did: user.domain, didWeb: user.didWeb },
        user,
      );
      await this.userRepository.update(
        { clerkId: user.clerkId },
        { didWebPendingVerifcation: false },
      );
    }
  }

  async disconnectDidWeb(clerkId: string) {
    const user = await this.userRepository.findOneBy({ clerkId });

    user.didWeb = null;
    user.didWebWellKnown = null;
    user.didWebPendingVerifcation = false;
    user.didWebWellKnownChangedAt = new Date();
    const updatedUser = await this.userRepository.save(user, { reload: true });

    await this.credentialsService.removeDidWebCredential(updatedUser);
    return updatedUser;
  }
}
