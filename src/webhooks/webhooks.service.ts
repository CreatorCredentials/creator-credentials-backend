import { Injectable, Logger } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { ClerkRole, User } from '../users/user.entity';

interface ClerkEmailAddress {
  email_address: string;
  id: string;
}

interface ClerkUserEventData {
  id: string;
  first_name?: string;
  last_name?: string;
  primary_email_address_id?: string;
  email_addresses?: ClerkEmailAddress[];
  public_metadata?: {
    role?: string;
    description?: string;
    name?: string;
    termsAreAccepted?: boolean;
    termsLink?: string;
  };
  unsafe_metadata?: {
    role?: string;
    description?: string;
    name?: string;
    termsAreAccepted?: boolean;
    termsLink?: string;
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
    const name = this.resolveNameMetadata(data);
    const email = this.primaryEmail(data);
    const { termsAreAccepted, termsLink } = this.resolveTermsMetadata(data);

    this.logger.log(
      `user.created: clerkId=${clerkId} role=${clerkRole} email=${email} name=${name} termsAreAccepted=${termsAreAccepted}`,
    );

    if (!termsAreAccepted || !termsLink) {
      this.logger.warn(
        `user.created: skipping DB creation for clerkId=${clerkId} — termsAreAccepted or termsLink not present in Clerk metadata. User will be created on user.updated once terms are set.`,
      );
      return;
    }

    await this.usersService.create({ clerkId, clerkRole, email, name, description, termsLink });
  }

  private async handleUserUpdated(data: ClerkUserEventData) {
    const { id: clerkId } = data;
    const newRole = this.resolveRole(this.resolveRoleMetadata(data));
    const description = this.resolveDescriptionMetadata(data);
    const name = this.resolveNameMetadata(data);
    const { termsAreAccepted, termsLink } = this.resolveTermsMetadata(data);
    this.logger.log(`user.updated: clerkId=${clerkId} role=${newRole} name=${name} termsAreAccepted=${termsAreAccepted}`);

    const existing = await this.usersService.getByClerkId(clerkId);
    if (!existing) {
      if (!termsAreAccepted || !termsLink) {
        this.logger.warn(
          `user.updated: skipping DB creation for clerkId=${clerkId} — termsAreAccepted or termsLink not present.`,
        );
        return;
      }
      // Webhook ordering edge-case: user.updated arrived before user.created,
      // or user.created was skipped due to missing terms and terms have now been set.
      const email = this.primaryEmail(data);
      await this.usersService.create({
        clerkId,
        clerkRole: newRole,
        email,
        name,
        description,
        termsLink,
      });
    } else if (
      existing.clerkRole !== newRole ||
      (description?.trim() && existing.description !== description.trim()) ||
      (name?.trim() && existing.name !== name.trim())
    ) {
      await this.usersService.updateClerkProfile(clerkId, {
        role: newRole,
        name,
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

  private resolveNameMetadata(data: ClerkUserEventData): string | undefined {
    // Prefer explicit name from metadata, then fall back to Clerk's firstName
    const metaName =
      data.public_metadata?.name ?? data.unsafe_metadata?.name;
    if (metaName?.trim()) return metaName.trim();

    const fromFirstName = [data.first_name, data.last_name]
      .filter(Boolean)
      .join(' ')
      .trim();
    return fromFirstName || undefined;
  }

  private resolveTermsMetadata(data: ClerkUserEventData): {
    termsAreAccepted: boolean;
    termsLink: string | undefined;
  } {
    const termsAreAccepted =
      data.public_metadata?.termsAreAccepted ??
      data.unsafe_metadata?.termsAreAccepted ??
      false;
    const termsLink =
      data.public_metadata?.termsLink ?? data.unsafe_metadata?.termsLink;
    return { termsAreAccepted: Boolean(termsAreAccepted), termsLink };
  }
}
