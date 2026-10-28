export const MAILER = 'MAILER';

export type MailMessage = {
  to: string[];
  subject: string;
  text: string;
  html: string;
};

/** A message before its recipients are resolved. */
export type MailContent = Omit<MailMessage, 'to'>;

export interface MailerPort {
  send(message: MailMessage): Promise<void>;
}
