import type { LoaderContext } from '../types/loader';

export type L402Token = {
  credential: string;
  maxBandwidth: number;
  expiry?: number;
};

export type L402Challenge = {
  macaroon: string;
  invoice: string;
};

export function parseL402Challenge(header: string): L402Challenge | null {
  const match = header.match(
    /L402\s+macaroon="([^"]+)",\s*invoice="([^"]+)"/,
  );
  if (match) {
    return { macaroon: match[1], invoice: match[2] };
  }
  return null;
}

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
