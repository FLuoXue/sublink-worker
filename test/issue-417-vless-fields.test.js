import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';
import { parseTuic } from '../src/parsers/protocols/tuicParser.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

const UUID = '00000000-0000-4000-8000-000000000001';
const ENCRYPTION = 'mlkem768x25519plus.native.0rtt.dGVzdA';

const buildVlessUrl = (params = '', name = 'test-node') =>
    `vless://${UUID}@203.0.113.10:443?${params}#${encodeURIComponent(name)}`;

const XHTTP_PARAMS = [
    `encryption=${ENCRYPTION}`,
    'flow=xtls-rprx-vision',
    'security=reality',
    'sni=example.com',
    'fp=chrome',
    'pbk=public-key',
    'sid=abcd',
    'type=xhttp',
    'path=test-xh',
    'mode=auto',
    'host=cdn.example.com',
    'alpn=h2',
    'packet_encoding=xudp'
].join('&');

const XHTTP_URL = buildVlessUrl(XHTTP_PARAMS);

const createTestApp = () => createApp({
    kv: new MemoryKVAdapter(),
    assetFetcher: null,
    logger: console,
    config: {
        configTtlSeconds: 60,
        shortLinkTtlSeconds: null
    }
});

const buildClash = async (input) => {
    const builder = new ClashConfigBuilder(input, 'minimal', [], null, 'zh-CN', 'test-agent');
    return yaml.load(await builder.build());
};

const buildSingbox = async (input) => {
    const builder = new SingboxConfigBuilder(input, 'minimal', [], null, 'zh-CN', 'test-agent', false);
    return builder.build();
};

describe('Issue #417 - VLESS share link fields', () => {
    it('keeps encryption, alpn and packet_encoding from the share link', () => {
        const parsed = parseVless(XHTTP_URL);

        expect(parsed.encryption).toBe(ENCRYPTION);
        expect(parsed.alpn).toEqual(['h2']);
        expect(parsed.packet_encoding).toBe('xudp');
    });

    it('treats `encryption=none` as no encryption', () => {
        const parsed = parseVless(buildVlessUrl('security=tls&encryption=none&type=tcp'));

        expect(parsed.encryption).toBeUndefined();
    });

    it('keeps xhttp transport mode/path/host', () => {
        const parsed = parseVless(XHTTP_URL);

        expect(parsed.transport).toMatchObject({
            type: 'xhttp',
            path: 'test-xh',
            host: 'cdn.example.com',
            mode: 'auto'
        });
    });

    it('normalizes the legacy splithttp transport name to xhttp', () => {
        const parsed = parseVless(buildVlessUrl('security=tls&type=splithttp&path=/split&mode=packet-up'));

        expect(parsed.transport.type).toBe('xhttp');
        expect(parsed.transport.mode).toBe('packet-up');
    });

    it('parses insecure=0 as false and insecure=1 as true', () => {
        expect(parseVless(buildVlessUrl('security=tls&insecure=0')).tls.insecure).toBe(false);
        expect(parseVless(buildVlessUrl('security=tls&insecure=1')).tls.insecure).toBe(true);
        expect(parseVless(buildVlessUrl('security=tls&allowInsecure=1')).tls.insecure).toBe(true);
    });
});

describe('Issue #417 - Clash output', () => {
    it('emits encryption, xhttp-opts, alpn and packet-encoding for VLESS', async () => {
        const built = await buildClash(XHTTP_URL);
        const proxy = built.proxies.find(p => p.name === 'test-node');

        expect(proxy).toBeDefined();
        expect(proxy.network).toBe('xhttp');
        expect(proxy.encryption).toBe(ENCRYPTION);
        expect(proxy['xhttp-opts']).toEqual({
            path: 'test-xh',
            host: 'cdn.example.com',
            mode: 'auto'
        });
        expect(proxy.alpn).toEqual(['h2']);
        expect(proxy['packet-encoding']).toBe('xudp');
        expect(proxy['skip-cert-verify']).toBe(false);
    });

    it('does not drop nodes that differ only by alpn', async () => {
        const first = buildVlessUrl('security=tls&sni=a.example.com&alpn=h3', 'node-a');
        const second = buildVlessUrl('security=tls&sni=a.example.com&alpn=h2,http/1.1', 'node-b');

        const built = await buildClash(`${first}\n${second}`);
        const names = built.proxies.map(p => p.name);

        expect(names).toContain('node-a');
        expect(names).toContain('node-b');
    });

    it('maps insecure=0 to skip-cert-verify: false', async () => {
        const built = await buildClash(buildVlessUrl('security=tls&sni=a.example.com&insecure=0'));
        const proxy = built.proxies.find(p => p.name === 'test-node');

        expect(proxy['skip-cert-verify']).toBe(false);
    });

    it('defaults TUIC skip-cert-verify to false', async () => {
        const insecureByDefault = parseTuic('tuic://user:pass@example.com:443?sni=example.com#tuic-default');
        const insecureOptOut = parseTuic('tuic://user:pass@example.com:443?sni=example.com&insecure=1#tuic-insecure');

        expect(insecureByDefault.tls.insecure).toBe(false);
        expect(insecureOptOut.tls.insecure).toBe(true);

        const built = await buildClash('tuic://user:pass@example.com:443?sni=example.com#tuic-default');
        const proxy = built.proxies.find(p => p.name === 'tuic-default');
        expect(proxy['skip-cert-verify']).toBe(false);
    });
});

describe('Issue #417 - sing-box output', () => {
    it('converts xhttp transport and strips fields sing-box rejects', async () => {
        const built = await buildSingbox(XHTTP_URL);
        const outbound = built.outbounds.find(o => o.tag === 'test-node');

        expect(outbound).toBeDefined();
        expect(outbound.transport.type).toBe('http');
        expect(outbound.transport.mode).toBeUndefined();
        expect(outbound.encryption).toBeUndefined();
        expect(outbound.packet_encoding).toBeUndefined();
    });
});

describe('Issue #417 - short links serve configs directly', () => {
    it('returns the Clash config instead of redirecting to a long URL', async () => {
        const app = createTestApp();
        const longUrl = `http://localhost/clash?config=${encodeURIComponent(XHTTP_URL)}&selectedRules=minimal`;

        const shortenRes = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent(longUrl)}`);
        expect(shortenRes.status).toBe(200);
        const code = (await shortenRes.text()).trim();
        expect(code).not.toBe('');

        const res = await app.request(`http://localhost/c/${code}`);
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('yaml');
        const built = yaml.load(await res.text());
        expect(built.proxies.some(p => p.name === 'test-node')).toBe(true);
    });

    it('returns the sing-box config for /b/:code', async () => {
        const app = createTestApp();
        const longUrl = `http://localhost/singbox?config=${encodeURIComponent(XHTTP_URL)}`;

        const shortenRes = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent(longUrl)}`);
        const code = (await shortenRes.text()).trim();

        const res = await app.request(`http://localhost/b/${code}`);
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json.outbounds.some(o => o.tag === 'test-node')).toBe(true);
    });
});

describe('Issue #417 - custom rules persistence', () => {
    it('wires custom rules to localStorage so a reload keeps them', async () => {
        const app = createTestApp();
        const res = await app.request('http://localhost/');
        const html = await res.text();

        expect(html).toContain("localStorage.getItem('customRules')");
        expect(html).toContain("localStorage.setItem('customRules'");
        expect(html).toContain("localStorage.removeItem('customRules')");
    });
});
