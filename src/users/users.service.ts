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

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private credentialsService: CredentialsService,
    private configService: ConfigService,
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
    //TODO: Also remove wallet credential here
    return updatedUser;
  }
}
