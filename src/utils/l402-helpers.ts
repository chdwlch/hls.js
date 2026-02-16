import type { LoaderContext } from '../types/loader';

export type L402Token = {
  credential: string;
  maxBandwidth: number;
  expiry?: number;
};

export type L402Challenge = {
  macaroon: string;
  invoice: string;
  maxBandwidth: number;
  expiry: number;
};

// --- Caveat condition constants (matching l402-js) ---

const MAX_BANDWIDTH_CONDITION = 'max_bandwidth';
const EXPIRATION_CONDITION = 'expiration';

// --- Macaroon v2 binary field types ---

const FIELD_EOS = 0;
const FIELD_IDENTIFIER = 2;
const FIELD_SIGNATURE = 6;

// --- Base64 / Binary helpers ---

function base64ToBytes(str: string): Uint8Array {
  // Handle both standard base64 and base64url encoding
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function readVarint(data: Uint8Array, pos: number): [number, number] {
  let value = 0;
  let shift = 0;
  while (pos < data.length) {
    const b = data[pos++];
    value |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      break;
    }
    shift += 7;
  }
  return [value, pos];
}

function bytesToString(data: Uint8Array, start: number, len: number): string {
  const chars: string[] = [];
  for (let i = 0; i < len; i++) {
    chars.push(String.fromCharCode(data[start + i]));
  }
  return chars.join('');
}

// --- Caveat parsing ---

/**
 * Decode a caveat string of the form "condition[=<>]value" into its parts.
 * Returns null if the string does not contain a valid comparator.
 */
export function decodeCaveat(
  str: string,
): { condition: string; comp: string; value: string } | null {
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '=' || ch === '<' || ch === '>') {
      return {
        condition: str.slice(0, i).trim(),
        comp: ch,
        value: str.slice(i + 1).trim(),
      };
    }
  }
  return null;
}

/**
 * Extract first-party caveat strings from a base64-encoded macaroon.
 * Supports macaroon v2 binary format (produced by js-macaroon / l402-js)
 * and v1 packet format.
 */
export function extractCaveatsFromMacaroon(base64Macaroon: string): string[] {
  try {
    const data = base64ToBytes(base64Macaroon);
    if (data.length < 2) {
      return [];
    }
    // v2 binary format starts with 0x02
    if (data[0] === 2) {
      return extractCaveatsV2(data);
    }
    // v1 packet format (ASCII text-based)
    return extractCaveatsV1(data);
  } catch {
    return [];
  }
}

/**
 * Parse macaroon v2 binary format to extract caveat identifier strings.
 * Format: version(1B) | header-section | caveat-sections... | signature-section
 * Each section has fields: type(varint) length(varint) data(bytes), ended by EOS(0).
 */
function extractCaveatsV2(data: Uint8Array): string[] {
  const caveats: string[] = [];
  let pos = 1; // skip version byte (0x02)
  let isFirstSection = true;

  while (pos < data.length) {
    const [fieldType, p1] = readVarint(data, pos);
    pos = p1;

    if (fieldType === FIELD_EOS) {
      isFirstSection = false;
      continue;
    }

    const [fieldLen, p2] = readVarint(data, pos);
    pos = p2;

    if (pos + fieldLen > data.length) {
      break;
    }

    // Identifier fields in non-first sections are caveat identifiers
    if (fieldType === FIELD_IDENTIFIER && !isFirstSection) {
      caveats.push(bytesToString(data, pos, fieldLen));
    }

    // Signature field means we're done
    if (fieldType === FIELD_SIGNATURE) {
      break;
    }

    pos += fieldLen;
  }

  return caveats;
}

/**
 * Parse macaroon v1 packet format to extract caveat identifier strings.
 * Format: packets of [4-hex-len][key ][data]\n where key "cid" = first-party caveat.
 */
function extractCaveatsV1(data: Uint8Array): string[] {
  const caveats: string[] = [];
  let pos = 0;

  while (pos + 8 < data.length) {
    const lenHex = bytesToString(data, pos, 4);
    const packetLen = parseInt(lenHex, 16);
    if (isNaN(packetLen) || packetLen < 9 || pos + packetLen > data.length) {
      break;
    }
    // Key starts at pos+4, find the space separator
    const packetData = bytesToString(data, pos + 4, packetLen - 4);
    const spaceIdx = packetData.indexOf(' ');
    if (spaceIdx > -1) {
      const key = packetData.slice(0, spaceIdx);
      // v1 caveat identifiers use key "cid"
      if (key === 'cid') {
        // data runs from after the space to end minus trailing newline
        let value = packetData.slice(spaceIdx + 1);
        if (value.endsWith('\n')) {
          value = value.slice(0, -1);
        }
        caveats.push(value);
      }
    }
    pos += packetLen;
  }

  return caveats;
}

/**
 * Extract the max_bandwidth caveat value from a base64-encoded macaroon.
 * Returns 0 if the caveat is not present. If multiple max_bandwidth caveats
 * exist, the last one wins (most restrictive / latest).
 */
export function getMaxBandwidthFromMacaroon(base64Macaroon: string): number {
  const caveats = extractCaveatsFromMacaroon(base64Macaroon);
  let maxBandwidth = 0;
  for (const cavStr of caveats) {
    const cav = decodeCaveat(cavStr);
    if (cav && cav.condition === MAX_BANDWIDTH_CONDITION) {
      maxBandwidth = Number(cav.value) || 0;
    }
  }
  return maxBandwidth;
}

/**
 * Extract the expiration caveat value from a base64-encoded macaroon.
 * Returns 0 if the caveat is not present. If multiple expiration caveats
 * exist, the last one wins (most restrictive / latest).
 */
export function getExpirationFromMacaroon(base64Macaroon: string): number {
  const caveats = extractCaveatsFromMacaroon(base64Macaroon);
  let expiration = 0;
  for (const cavStr of caveats) {
    const cav = decodeCaveat(cavStr);
    if (cav && cav.condition === EXPIRATION_CONDITION) {
      expiration = Number(cav.value) || 0;
    }
  }
  return expiration;
}

// --- L402 challenge parsing ---

/**
 * Parse a WWW-Authenticate header containing an L402 challenge.
 * Handles both L402 and LSAT prefixes, comma or space separators,
 * and challenge parts in any order. Extracts maxBandwidth and expiry
 * from the challenge macaroon caveats.
 */
export function parseL402Challenge(header: string): L402Challenge | null {
  // Strip L402 or LSAT type prefix
  let challenge = header;
  const prefixMatch = header.match(/^(?:L402|LSAT)\s+/i);
  if (prefixMatch) {
    challenge = header.slice(prefixMatch[0].length);
  }

  // Extract key="value" pairs (handles any order and separator)
  let macaroon = '';
  let invoice = '';
  const pairRegex = /(\w+)="([^"]*)"/g;
  let match: RegExpExecArray | null;
  while ((match = pairRegex.exec(challenge)) !== null) {
    const key = match[1].toLowerCase();
    if (key === 'macaroon') {
      macaroon = match[2];
    } else if (key === 'invoice') {
      invoice = match[2];
    }
  }

  if (!macaroon || !invoice) {
    return null;
  }

  const maxBandwidth = getMaxBandwidthFromMacaroon(macaroon);
  const expiry = getExpirationFromMacaroon(macaroon);

  return { macaroon, invoice, maxBandwidth, expiry };
}

/**
 * Extract an L402 challenge from the network response's WWW-Authenticate header.
 */
export function getL402ChallengeFromNetworkDetails(
  networkDetails: any,
): L402Challenge | null {
  if (!networkDetails) {
    return null;
  }
  let header: string | null = null;
  if (typeof networkDetails.getResponseHeader === 'function') {
    header = networkDetails.getResponseHeader('WWW-Authenticate');
  } else if (
    networkDetails.headers &&
    typeof networkDetails.headers.get === 'function'
  ) {
    header = networkDetails.headers.get('WWW-Authenticate');
  }
  if (!header) {
    return null;
  }
  return parseL402Challenge(header);
}

// --- L402 credential parsing ---

/**
 * Parse a credential string (macaroon:preimage) and extract maxBandwidth
 * and expiry from the macaroon caveats.
 */
export function parseL402Credential(credential: string): {
  maxBandwidth: number;
  expiry: number;
} {
  const colonIdx = credential.indexOf(':');
  const macaroon = colonIdx > -1 ? credential.slice(0, colonIdx) : credential;
  return {
    maxBandwidth: getMaxBandwidthFromMacaroon(macaroon),
    expiry: getExpirationFromMacaroon(macaroon),
  };
}

// --- Header injection ---

/**
 * Apply the L402 Authorization header to a loader context if a valid token exists.
 * Skips injection if the token has expired.
 */
export function applyL402Header(
  context: LoaderContext,
  token: L402Token | null,
): void {
  if (token?.credential) {
    if (token.expiry && Date.now() > token.expiry) {
      return;
    }
    if (!context.headers) {
      context.headers = {};
    }
    context.headers.Authorization = `L402 ${token.credential}`;
  }
}
