import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

const upstreamUrl = 'https://airport.example.com/api/v1/client/subscribe?token=abc';
const proxyUri = 'ss://YWVzLTEyOC1nY206cGFzcw@example.com:443#HwidNode';

function createTestApp() {
    return createApp({
        kv: new MemoryKVAdapter(),
        assetFetcher: null,
        logger: console,
        config: {
            configTtlSeconds: 60,
            shortLinkTtlSeconds: null
        }
    });
}

function mockUpstreamFetch() {
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
        calls.push({ url: String(url), headers: init?.headers });
        return {
            ok: true,
            status: 200,
            text: async () => proxyUri,
            headers: { get: () => null }
        };
    }));
    return calls;
}

const configParam = encodeURIComponent(upstreamUrl);

describe('HWID passthrough', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('forwards the X-HWID header to the upstream subscription', async () => {
        const calls = mockUpstreamFetch();
        const app = createTestApp();

        await app.request(`http://localhost/clash?config=${configParam}`, {
            headers: { 'X-HWID': 'device-header' }
        });

        expect(calls).toHaveLength(1);
        expect(calls[0].headers.get('X-HWID')).toBe('device-header');
    });

    it('appends the hwid query parameter to the upstream subscription', async () => {
        const calls = mockUpstreamFetch();
        const app = createTestApp();

        await app.request(`http://localhost/clash?config=${configParam}&hwid=device-query`);

        expect(calls).toHaveLength(1);
        expect(calls[0].url).toContain('hwid=device-query');
        expect(calls[0].url).toContain('token=abc');
    });

    it('leaves the upstream request untouched when no hwid is sent', async () => {
        const calls = mockUpstreamFetch();
        const app = createTestApp();

        await app.request(`http://localhost/clash?config=${configParam}`);

        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe(upstreamUrl);
        expect(calls[0].headers.get('X-HWID')).toBeNull();
    });

    it('forwards hwid for sing-box and surge targets too', async () => {
        for (const target of ['singbox', 'surge']) {
            const calls = mockUpstreamFetch();
            const app = createTestApp();

            await app.request(`http://localhost/${target}?config=${configParam}`, {
                headers: { 'X-HWID': `device-${target}` }
            });

            expect(calls[0]?.headers.get('X-HWID')).toBe(`device-${target}`);
            vi.unstubAllGlobals();
        }
    });
});
