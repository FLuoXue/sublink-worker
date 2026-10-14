import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool, parseArray } from '../../utils.js';

export function parseVless(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const [uuid, serverInfo] = addressPart.split('@');
    const { host, port } = parseServerInfo(serverInfo);

    const tls = createTlsConfig(params);
    if (tls.reality) {
        tls.utls = {
            enabled: true,
            fingerprint: 'chrome'
        };
    }
    const transport = params.type !== 'tcp' ? createTransportConfig(params) : undefined;

    // `udp` is a Clash-only flag; ClashConfigBuilder reads it, SingboxConfigBuilder strips it.
    const udp = params.udp !== undefined ? parseBool(params.udp) : undefined;

    // Xray emits `encryption=none` for plain VLESS; only post-quantum values are meaningful here.
    const encryption = params.encryption && params.encryption !== 'none' ? params.encryption : undefined;

    return {
        type: 'vless',
        tag: name,
        server: host,
        server_port: port,
        uuid: decodeURIComponent(uuid),
        tcp_fast_open: false,
        tls,
        transport,
        flow: params.flow ?? undefined,
        alpn: parseArray(params.alpn),
        packet_encoding: params.packet_encoding ?? params.packetEncoding,
        encryption,
        ...(udp !== undefined ? { udp } : {})
    };
}
