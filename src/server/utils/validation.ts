export function isValidIp(ip: string): boolean {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return ip.split('.').every(n => parseInt(n, 10) <= 255);
  }
  if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':') && ip.length <= 39) {
    return true;
  }
  return false;
}

export function looksLikeDomain(input: string): boolean {
  const clean = input.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(clean);
}

export function cleanDomainInput(input: string): string {
  return input.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
}

/** Returns true if the input passes the ip field regex used in /analyze */
export function isValidAnalyzeIp(ip: string): boolean {
  return /^[a-zA-Z0-9.\-:]+$/.test(ip);
}
