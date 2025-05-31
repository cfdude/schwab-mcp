import { sanitizeHtml } from './approvalDialog';

export const APPROVAL_CSS = /*css*/ `
/* Modern, responsive styling with system fonts */
:root {
  --primary-color: #0070f3;
  --error-color: #f44336;
  --border-color: #e5e7eb;
  --text-color: #333;
  --background-color: #fff;
  --card-shadow: 0 8px 36px 8px rgba(0, 0, 0, 0.1);
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, 
               Helvetica, Arial, sans-serif, "Apple Color Emoji", 
               "Segoe UI Emoji", "Segoe UI Symbol";
  line-height: 1.6;
  color: var(--text-color);
  background-color: #f9fafb;
  margin: 0;
  padding: 0;
}

.container {
  max-width: 600px;
  margin: 2rem auto;
  padding: 1rem;
}

.precard {
  padding: 2rem;
  text-align: center;
}

.card {
  background-color: var(--background-color);
  border-radius: 8px;
  box-shadow: var(--card-shadow);
  padding: 2rem;
}

.header {
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1.5rem;
}

.logo {
  width: 48px;
  height: 48px;
  margin-right: 1rem;
  border-radius: 8px;
  object-fit: contain;
}

.title {
  margin: 0;
  font-size: 1.3rem;
  font-weight: 400;
}

.alert {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 400;
  margin: 1rem 0;
  text-align: center;
}

.description {
  color: #555;
}

.warning {
  background-color: #fff3e0;
  border: 1px solid #ff9800;
  border-radius: 6px;
  padding: 1rem;
  margin-bottom: 1.5rem;
  color: #e65100;
}

.warning-icon {
  display: inline-block;
  margin-right: 0.5rem;
}

.client-info {
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 1rem 1rem 0.5rem;
  margin-bottom: 1.5rem;
}

.client-name {
  font-weight: 600;
  font-size: 1.2rem;
  margin: 0 0 0.5rem 0;
}

.client-detail {
  display: flex;
  margin-bottom: 0.5rem;
  align-items: baseline;
}

.detail-label {
  font-weight: 500;
  min-width: 120px;
}

.detail-value {
  font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  word-break: break-all;
}

.detail-value a {
  color: inherit;
  text-decoration: underline;
}

.detail-value.small {
  font-size: 0.8em;
}

.external-link-icon {
  font-size: 0.75em;
  margin-left: 0.25rem;
  vertical-align: super;
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  margin-top: 2rem;
}

.button {
  padding: 0.75rem 1.5rem;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  border: none;
  font-size: 1rem;
}

.button-primary {
  background-color: var(--primary-color);
  color: white;
}

.button-secondary {
  background-color: transparent;
  border: 1px solid var(--border-color);
  color: var(--text-color);
}

/* Responsive adjustments */
@media (max-width: 640px) {
  .container {
    margin: 1rem auto;
    padding: 0.5rem;
  }
  
  .card {
    padding: 1.5rem;
  }
  
  .client-detail {
    flex-direction: column;
  }
  
  .detail-label {
    min-width: unset;
    margin-bottom: 0.25rem;
  }
  
  .actions {
    flex-direction: column;
  }
  
  .button {
    width: 100%;
  }
}
`;

interface ApprovalDialogTemplateParams {
  client: {
    clientId: string;
    name: string;
    website?: string;
    logoUri?: string;
    policyUri?: string;
    tosUri?: string;
    redirectUris?: string[];
    contacts?: string[];
  };
  server: {
    name: string;
    logoUri?: string;
    description?: string;
  };
  encodedState: string;
  warnAboutUntrustedClient: boolean;
  formActionPath: string;
}

export function createApprovalDialogHTML(params: ApprovalDialogTemplateParams): string {
  const { client, server, encodedState, warnAboutUntrustedClient, formActionPath } = params;
  
  return /*html*/ `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authorize ${sanitizeHtml(client.name)}</title>
      <style>${APPROVAL_CSS}</style>
    </head>
    <body>
      <div class="container">
        <div class="precard">
          <div class="header">
            ${server.logoUri ? `<img src="${sanitizeHtml(server.logoUri)}" alt="${sanitizeHtml(server.name)} Logo" class="logo">` : ''}
          <h1 class="title"><strong>${sanitizeHtml(server.name)}</strong></h1>
          </div>
          
          ${server.description ? `<p class="description">${sanitizeHtml(server.description)}</p>` : ''}
        </div>
          
        <div class="card">
          
          <h2 class="alert"><strong>${sanitizeHtml(client.name) || 'A new MCP Client'}</strong> is requesting access</h2>
          
          ${
            warnAboutUntrustedClient
              ? /*html*/ `
            <div class="warning">
              <span class="warning-icon">⚠️</span>
              <strong>Security Warning:</strong> Some redirect URIs provided by this client are not in the allowed list and have been filtered out for your security.
            </div>
          `
              : ''
          }
          
          <div class="client-info">
            <div class="client-detail">
              <div class="detail-label">Name:</div>
              <div class="detail-value">
                ${sanitizeHtml(client.name)}
              </div>
            </div>
            
            ${
              client.website
                ? /*html*/ `
              <div class="client-detail">
                <div class="detail-label">Website:</div>
                <div class="detail-value small">
                  <a href="${sanitizeHtml(client.website)}" target="_blank" rel="noopener noreferrer">
                    ${sanitizeHtml(client.website)}
                  </a>
                </div>
              </div>
            `
                : ''
            }
            
            ${
              client.policyUri
                ? /*html*/ `
              <div class="client-detail">
                <div class="detail-label">Privacy Policy:</div>
                <div class="detail-value">
                  <a href="${sanitizeHtml(client.policyUri)}" target="_blank" rel="noopener noreferrer">
                    ${sanitizeHtml(client.policyUri)}
                  </a>
                </div>
              </div>
            `
                : ''
            }
            
            ${
              client.tosUri
                ? /*html*/ `
              <div class="client-detail">
                <div class="detail-label">Terms of Service:</div>
                <div class="detail-value">
                  <a href="${sanitizeHtml(client.tosUri)}" target="_blank" rel="noopener noreferrer">
                    ${sanitizeHtml(client.tosUri)}
                  </a>
                </div>
              </div>
            `
                : ''
            }
            
            ${
              client.redirectUris && client.redirectUris.length > 0
                ? /*html*/ `
              <div class="client-detail">
                <div class="detail-label">Redirect URIs:</div>
                <div class="detail-value small">
                  ${client.redirectUris.map((uri) => `<div>${sanitizeHtml(uri)}</div>`).join('')}
                </div>
              </div>
            `
                : ''
            }
            
            ${
              client.contacts && client.contacts.length > 0
                ? /*html*/ `
              <div class="client-detail">
                <div class="detail-label">Contact:</div>
                <div class="detail-value">${client.contacts.map((contact) => sanitizeHtml(contact)).join(', ')}</div>
              </div>
            `
                : ''
            }
          </div>
          
          <p>This MCP Client is requesting to be authorized on ${sanitizeHtml(server.name)}. If you approve, you will be redirected to complete authentication.</p>
          
          <form method="post" action="${formActionPath}">
            <input type="hidden" name="state" value="${sanitizeHtml(encodedState)}">
            
            <div class="actions">
              <button type="button" class="button button-secondary" onclick="window.history.back()">Cancel</button>
              <button type="submit" class="button button-primary">Approve</button>
            </div>
          </form>
        </div>
      </div>
    </body>
    </html>
  `;
}