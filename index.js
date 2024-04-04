export function endianness() {
    const buf = Memory.alloc(4);
    buf.writeU32(1);
    return buf.readU8() === 1 ? 'LE' : 'BE';
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
export function totalmem() {
    if (Process.platform === 'windows') {
        const kernel32 = Process.getModuleByName('kernel32.dll');
        const getPerformanceInfo = kernel32.getExportByName('GetPerformanceInfo');
        if (getPerformanceInfo !== null) {
            const performanceInfoSize = 64;
            const performanceInfo = Memory.alloc(performanceInfoSize);
            const lpPerformanceInformation = performanceInfo;
            const cb = performanceInfoSize;
            if (getPerformanceInfo(lpPerformanceInformation, cb)) {
                return lpPerformanceInformation.add(8).readU64();
            }
        }
    }
    else if (Process.platform === 'android') {
        const activityManager = Java.use('android.app.ActivityManager');
        const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        const memoryInfo = new activityManager.MemoryInfo();
        activityManager.getMemoryInfo(memoryInfo);
        return memoryInfo.totalMem;
    }
    else if (Process.platform === 'linux') {
        const fd = new File('/proc/meminfo', "r");
        let meminfoContent = '';
        let line;
        while ((line = fd.readLine()) !== null) {
            meminfoContent += line + '\n';
        }
        fd.close();
        const lines = meminfoContent.split('\n');
        for (let line of lines) {
            if (line.startsWith('MemTotal:')) {
                const parts = line.split(/\s+/);
                return parseInt(parts[1]);
            }
        }
    }
    else if (Process.platform === 'darwin') {
        const libc = Process.getModuleByName('libc.dylib');
        if (libc !== null) {
            const mib = Memory.alloc(4 * 2);
            mib.writeByteArray([2, 5]);
            const len = Memory.alloc(4);
            len.writeUInt(8);
            const memsize = Memory.alloc(8);
            if (libc.sysctl(mib, 2, memsize, len, 0, 0) === 0) {
                return memsize.readU64();
            }
        }
    }
    return Number.MAX_VALUE;
}
export function freemem() {
    if (Process.platform === 'windows') {
        const kernel32 = Process.getModuleByName('kernel32.dll');
        const globalMemoryStatusEx = kernel32.getExportByName('GlobalMemoryStatusEx');
        if (globalMemoryStatusEx !== null) {
            const memoryStatusExSize = 64;
            const memoryStatusEx = Memory.alloc(memoryStatusExSize);
            memoryStatusEx.writeU32(memoryStatusExSize);
            if (globalMemoryStatusEx(memoryStatusEx)) {
                return memoryStatusEx.add(8).readU64();
            }
        }
    }
    else if (Process.platform === 'android') {
        const activityManager = Java.use('android.app.ActivityManager');
        const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        const memoryInfo = new activityManager.MemoryInfo();
        activityManager.getMemoryInfo(memoryInfo);
        return memoryInfo.availMem;
    }
    else if (Process.platform === 'linux') {
        const fd = new File('/proc/meminfo', "r");
        let meminfoContent = '';
        let line;
        while ((line = fd.readLine()) !== null) {
            meminfoContent += line + '\n';
        }
        fd.close();
        const lines = meminfoContent.split('\n');
        let freeMem = 0;
        for (let line of lines) {
            if (line.startsWith('MemFree:')) {
                const parts = line.split(/\s+/);
                freeMem += parseInt(parts[1]);
                return freeMem;
            }
            else if (line.startsWith('Cached:')) {
                const parts = line.split(/\s+/);
                freeMem += parseInt(parts[1]);
                return freeMem;
            }
        }
    }
    else if (Process.platform === 'darwin') {
        const libc = Process.getModuleByName('libc.dylib');
        if (libc !== null) {
            const mib = Memory.alloc(4 * 2);
            mib.writeByteArray([6, 0]);
            const len = Memory.alloc(4);
            len.writeUInt(8);
            const memsize = Memory.alloc(8);
            if (libc.sysctl(mib, 2, memsize, len, 0, 0) === 0) {
                const pageSize = Process.pageSize;
                const vmstats = new NativeFunction(Module.findExportByName('libSystem.B.dylib', 'vm_statistics64'), 'int', ['pointer', 'pointer']);
                const VM_PAGE_SIZE = pageSize;
                const HOST_VM_INFO64_COUNT = 64;
                const hostSize = HOST_VM_INFO64_COUNT * Process.pointerSize;
                const hostInfo = Memory.alloc(hostSize);
                if (vmstats(hostInfo, len) === 0) {
                    const data = hostInfo.readByteArray(hostSize);
                    const info = new Uint32Array(data.buffer, data.byteOffset, data.byteLength / Uint32Array.BYTES_PER_ELEMENT);
                    const freePages = info[9];
                    return freePages * VM_PAGE_SIZE;
                }
            }
        }
    }
    return Number.MAX_VALUE;
}
export function cpus() {
    return [];
}
export function type() {
    const p = Process.platform;
    if (p === 'windows')
        return 'Windows_NT';
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
    const p = Process.platform;
    if (p === 'windows')
        return 'win32';
    return p;
}
export function tmpdir() {
    return Process.getTmpDir();
}
export const EOL = Process.platform === 'windows' ? '\r\n' : '\n';
export function homedir() {
    return Process.getHomeDir();
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
