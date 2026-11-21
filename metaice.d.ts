import { Buffer } from 'node:buffer';
import { Socket as UdpSocket } from 'node:dgram';
import { Socket } from 'node:net';

type StunKind = 'request' | 'indication' | 'success' | 'error';

interface StunAttribute {
  type: number;
  value: Buffer;
}

interface StunDecodedAttribute extends StunAttribute {
  offset: number;
}

interface StunMessage {
  type: number;
  method: number;
  kind: StunKind;
  length: number;
  transactionId: Buffer;
  attributes: StunDecodedAttribute[];
}

interface StunEncodeOptions {
  type: number;
  transactionId: Buffer;
  attributes: StunAttribute[];
  key?: string | Buffer | null;
  fingerprint?: boolean;
}

interface StunAddress {
  family: 'IPv4' | 'IPv6';
  address: string;
  port: number;
}

interface StunCodec {
  COOKIE: 0x2112a442;
  HEADER_SIZE: 20;
  FINGERPRINT_XOR: 0x5354554e;
  INTEGRITY_SIZE: 24;
  FINGERPRINT_SIZE: 8;
  CLASSES: StunKind[];
  METHODS: {
    binding: 0x001;
    allocate: 0x003;
    refresh: 0x004;
    send: 0x006;
    data: 0x007;
    createPermission: 0x008;
    channelBind: 0x009;
  };
  ATTRIBUTES: {
    mappedAddress: 0x0001;
    username: 0x0006;
    messageIntegrity: 0x0008;
    errorCode: 0x0009;
    unknownAttributes: 0x000a;
    channelNumber: 0x000c;
    lifetime: 0x000d;
    xorPeerAddress: 0x0012;
    data: 0x0013;
    realm: 0x0014;
    nonce: 0x0015;
    xorRelayedAddress: 0x0016;
    requestedTransport: 0x0019;
    xorMappedAddress: 0x0020;
    software: 0x8022;
    fingerprint: 0x8028;
  };
  typeOf(method: number, kind: StunKind): number;
  methodOf(type: number): number;
  classOf(type: number): StunKind;
  isStun(buffer: Buffer): boolean;
  decode(buffer: Buffer): StunMessage | null;
  find(message: StunMessage, type: number): StunDecodedAttribute | undefined;
  attribute(type: number, value: Buffer): Buffer;
  header(type: number, length: number, transactionId: Buffer): Buffer;
  encode(options: StunEncodeOptions): Buffer;
  hmac(key: string | Buffer, data: Buffer): Buffer;
  crc(data: Buffer): Buffer;
  verifyIntegrity(
    buffer: Buffer,
    message: StunMessage,
    key: string | Buffer,
  ): boolean;
  verifyFingerprint(buffer: Buffer, message: StunMessage): boolean;
  longTermKey(username: string, realm: string, password: string): Buffer;
  readAddress(value: Buffer, transactionId: Buffer): StunAddress;
  writeAddress(address: StunAddress, transactionId: Buffer): Buffer;
  parseV4(address: string): Buffer;
  parseV6(address: string): Buffer;
  formatV6(bytes: Buffer): string;
  errorCode(code: number, reason: string): Buffer;
}

declare const stun: StunCodec;

interface IceServerConsole {
  log(...data: unknown[]): void;
  info(...data: unknown[]): void;
  warn(...data: unknown[]): void;
  debug(...data: unknown[]): void;
  error(...data: unknown[]): void;
}

interface IceServerOptions {
  listen?: string;
  port?: number;
  tlsPort?: number;
  tls?: { key: string; cert: string } | null;
  publicAddress?: string;
  relayPorts?: [number, number];
  secret?: string;
  credentialTtl?: number;
  allocationsPerPeer?: number;
  allocationLifetime?: [number, number];
  permissionLifetime?: number;
  channelLifetime?: number;
  relayBitrate?: number;
  allowPrivatePeers?: boolean;
  realm?: string;
  software?: string;
  console?: IceServerConsole;
  host?: string;
  external?: IceServerEntry[];
}

interface IceServerPorts {
  udp: number;
  tcp: number;
  tls: number;
}

interface IceServerStats {
  allocations: number;
  sent: number;
  received: number;
  dropped: number;
}

declare class IceServer {
  constructor(options?: IceServerOptions);
  readonly ports: IceServerPorts;
  listen(): Promise<void>;
  stats(): IceServerStats;
  close(): Promise<void>;
}

interface IceThread {
  group: string;
  index: number;
  count: number;
}

interface IceRemote {
  address: string;
  port: number;
  family?: string | number;
}

interface IceConnectionInfo {
  port: number;
  transport: string;
  tls: boolean;
  servername: string;
  alpn: string;
  remote: IceRemote;
}

interface IceServiceContext {
  name: string;
  console: IceServerConsole;
  mode: string;
  protocols?: readonly string[];
  thread?: IceThread;
}

interface IceProviderContext extends IceServiceContext {
  thread: IceThread;
}

interface IceService {
  stop(): Promise<void>;
}

interface IceProvider extends IceService {
  connection(socket: Socket, info: IceConnectionInfo): void;
  datagram(buffer: Buffer, remote: IceRemote, socket: UdpSocket): void;
}

declare function start(
  options: IceServerOptions | undefined,
  context: IceProviderContext,
): Promise<IceProvider>;

declare function start(
  options?: IceServerOptions,
  context?: IceServiceContext,
): Promise<IceService>;

declare const protocols: readonly ['stun.turn', 'stun.nat-discovery'];

interface CredentialsOptions {
  secret: string;
  peer: string;
  credentialTtl?: number;
  now?: number;
}

interface TurnCredentials {
  username: string;
  credential: string;
  expiry: number;
}

interface IceServersOptions {
  name: string;
  port?: number;
  tlsPort?: number;
  secret?: string;
  peer?: string;
  credentialTtl?: number;
  now?: number;
}

interface IceServerEntry {
  urls: string[];
  username?: string;
  credential?: string;
}

declare function credentials(options: CredentialsOptions): TurnCredentials;
declare function iceServers(options: IceServersOptions): IceServerEntry[];
declare function isPrivate(address: string): boolean;

export {
  StunKind,
  StunAttribute,
  StunDecodedAttribute,
  StunMessage,
  StunEncodeOptions,
  StunAddress,
  StunCodec,
  stun,
  IceServerConsole,
  IceServerOptions,
  IceServerPorts,
  IceServerStats,
  IceServer,
  IceThread,
  IceRemote,
  IceConnectionInfo,
  IceServiceContext,
  IceProviderContext,
  IceService,
  IceProvider,
  start,
  protocols,
  CredentialsOptions,
  TurnCredentials,
  IceServersOptions,
  IceServerEntry,
  credentials,
  iceServers,
  isPrivate,
};
