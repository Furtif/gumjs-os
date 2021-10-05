export function endianness() {
  const buf = Memory.alloc(4);
  buf.writeU32(1);
  return (buf.readU8() === 1) ? 'LE' : 'BE';
}

export function hostname() {
  return '';
}

export function loadavg() {
  return [0, 0, 0];
}

export function uptime() {
  return 0;
}

export function freemem() {
  return Number.MAX_VALUE;
}

export function totalmem() {
  return Number.MAX_VALUE;
}

export function cpus() {
  return [];
}

export function type() {
  const p = Process.platform;
  return p[0].toUpperCase() + p.substr(1);
}

export function release() {
  return '';
}

export function networkInterfaces() {
  return {};
}

export function getNetworkInterfaces() {
  return {};
}

export function arch() {
  return Process.arch;
}

export function platform() {
  return Process.platform;
}

export function tmpdir() {
  return Process.tmpDir;
}

export const EOL = (Process.platform === 'windows') ? '\r\n' : '\n';

export function homedir() {
  return Process.homeDir;
}

export default {
  endianness,
  hostname,
  loadavg,
  uptime,
  freemem,
  totalmem,
  cpus,
  type,
  release,
  networkInterfaces,
  getNetworkInterfaces,
  arch,
  platform,
  tmpdir,
  EOL,
  homedir,
};
