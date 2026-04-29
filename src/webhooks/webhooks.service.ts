import { Injectable, Logger } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { ClerkRole, User } from '../users/user.entity';

interface ClerkEmailAddress {
  email_address: string;
  id: string;
}

interface ClerkUserEventData {
  id: string;
  primary_email_address_id?: string;
  email_addresses?: ClerkEmailAddress[];
  public_metadata?: {
    role?: string;
    description?: string;
  };
  unsafe_metadata?: {
    role?: string;
    description?: string;
  };
}

@Injectable()
export class WebhooksService {
  private readonly logger = new Logger(WebhooksService.name);

  constructor(private readonly usersService: UsersService) {}

  async handleEvent(event: { type: string; data: ClerkUserEventData }) {
    switch (event.type) {
      case 'user.created':
        await this.handleUserCreated(event.data);
        break;
      case 'user.updated':
        await this.handleUserUpdated(event.data);
        break;
      case 'user.deleted':
        await this.handleUserDeleted(event.data);
        break;
      default:
        this.logger.log(`Unhandled clerk webhook event: ${event.type}`);
    }
  }

  private async handleUserCreated(data: ClerkUserEventData) {
    const { id: clerkId } = data;
    const clerkRole = this.resolveRole(this.resolveRoleMetadata(data));
    const description = this.resolveDescriptionMetadata(data);
    const email = this.primaryEmail(data);
    this.logger.log(`user.created: clerkId=${clerkId} role=${clerkRole} email=${email}`);
    await this.usersService.create({ clerkId, clerkRole, email, description });
  }

  private async handleUserUpdated(data: ClerkUserEventData) {
    const { id: clerkId } = data;
    const newRole = this.resolveRole(this.resolveRoleMetadata(data));
    const description = this.resolveDescriptionMetadata(data);
    this.logger.log(`user.updated: clerkId=${clerkId} role=${newRole}`);

    const existing = await this.usersService.getByClerkId(clerkId);
    if (!existing) {
      // Webhook ordering edge-case: user.updated arrived before user.created
      const email = this.primaryEmail(data);
      await this.usersService.create({
        clerkId,
        clerkRole: newRole,
        email,
        description,
      });
    } else if (
      existing.clerkRole !== newRole ||
      (description?.trim() && existing.description !== description.trim())
    ) {
      await this.usersService.updateClerkProfile(clerkId, {
        role: newRole,
        description,
      });
    }
  }

  private async handleUserDeleted(data: ClerkUserEventData) {
    this.logger.log(`user.deleted: clerkId=${data.id}`);
    await this.usersService.deleteByClerkId(data.id);
  }

  private primaryEmail(data: ClerkUserEventData): string {
    const primary = data.email_addresses?.find(
      (e) => e.id === data.primary_email_address_id,
    );
    return primary?.email_address ?? data.email_addresses?.[0]?.email_address ?? '';
  }

  private resolveRole(roleMetadata?: string): ClerkRole {
    if (roleMetadata === 'ISSUER') return ClerkRole.Issuer;
    return ClerkRole.Creator;
  }

  private resolveRoleMetadata(data: ClerkUserEventData): string | undefined {
    return data.public_metadata?.role ?? data.unsafe_metadata?.role;
  }

  private resolveDescriptionMetadata(
    data: ClerkUserEventData,
  ): string | undefined {
    return data.public_metadata?.description ?? data.unsafe_metadata?.description;
  }
}
