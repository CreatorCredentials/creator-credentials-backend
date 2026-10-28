import { MailContent } from '../mailer.port';

export type MailLink = {
  label: string;
  path: string;
};

type MailDraft = {
  subject: string;
  lines: string[];
  link: MailLink;
};

/** Renders the plain-text body and the minimal HTML body every notification shares. */
export function renderMail(draft: MailDraft, appBaseUrl: string): MailContent {
  const url = appLink(appBaseUrl, draft.link.path);
  const text = [...draft.lines, '', `${draft.link.label}: ${url}`].join('\n');
  const paragraphs = draft.lines
    .map((line) => `<p>${escapeHtml(line)}</p>`)
    .join('');
  const html = `<!doctype html><html><body>${paragraphs}<p><a href="${escapeHtml(
    url,
  )}">${escapeHtml(draft.link.label)}</a></p></body></html>`;
  return { subject: draft.subject, text, html };
}

function appLink(appBaseUrl: string, path: string): string {
  return `${appBaseUrl.replace(/\/+$/, '')}${path}`;
}

function escapeHtml(value: string): string {
  const replacements: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return value.replace(/[&<>"']/g, (character) => replacements[character]);
}
