import { ClerkRole } from '../user.entity';

export class CreateUserDto {
  clerkRole: ClerkRole;
  clerkId: string;
  email: string;
  name?: string;
  description?: string;
}
