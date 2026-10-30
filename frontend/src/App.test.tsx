/** @vitest-environment jsdom */
import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from './App';

function mount(path: string) {
  return render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
}
function response(body: unknown) {
  return Promise.resolve({ ok: true, json: async () => body } as Response);
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('application states', () => {
  it('shows the dashboard empty state when there is no activity', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    mount('/');
    expect(await screen.findByText('No activity yet')).toBeInTheDocument();
  });

  it('shows a loading state and then the invalid verification result', async () => {
    let finish!: (value: Response) => void;
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(resolve => { finish = resolve; })));
    const user = userEvent.setup();
    mount('/verify');
    await user.upload(screen.getByLabelText(/Select document/), new File(['changed'], 'report.txt'));
    await user.upload(screen.getByLabelText(/Select \.zip or \.json/), new File(['{}'], 'signature.json', { type: 'application/json' }));
    await user.click(screen.getByRole('button', { name: 'Verify signature' }));
    expect(screen.getByText('Verifying…')).toBeInTheDocument();
    finish({ ok: true, json: async () => ({ valid: false, reason_code: 'signature_mismatch', digest: 'abc', fingerprint: 'def', message: 'Document content or signature does not match.' }) } as Response);
    expect(await screen.findByText('Signature is invalid')).toBeInTheDocument();
    expect(screen.getByText('signature_mismatch')).toBeInTheDocument();
  });

  it('shows a useful API error on verification failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('API unavailable')));
    const user = userEvent.setup();
    mount('/verify');
    await user.upload(screen.getByLabelText(/Select document/), new File(['file'], 'report.txt'));
    await user.upload(screen.getByLabelText(/Select \.zip or \.json/), new File(['{}'], 'signature.json', { type: 'application/json' }));
    await user.click(screen.getByRole('button', { name: 'Verify signature' }));
    expect(await screen.findByText('API unavailable')).toBeInTheDocument();
  });
});
