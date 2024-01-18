import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const newUser = new User();
    newUser.clerkId = createUserDto.clerkId;
    newUser.clerkRole = createUserDto.clerkRole;

    return this.userRepository.save(newUser, { reload: true });
  }

  async getByClerkId(clerkId: string): Promise<User> {
    return this.userRepository.findOne({ where: { clerkId } });
  }
}
