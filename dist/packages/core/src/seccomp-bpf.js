                                              
import { failSandbox } from './errors.js';

/**
 * Pure TypeScript Linux classic BPF (cBPF) compiler for `bwrap --seccomp <fd>`.
 * Zero external binary dependencies. Supports x86_64 and aarch64.
 */

// Classic BPF opcodes (<linux/filter.h>)
const BPF_LD_W_ABS = 0x20;
const BPF_ALU_AND_K = 0x54;
const BPF_JMP_JA = 0x05;
const BPF_JMP_JEQ_K = 0x15;
const BPF_JMP_JGE_K = 0x35;
const BPF_RET_K = 0x06;

// seccomp_data struct offsets (little-endian)
const OFF_NR = 0;
const OFF_ARCH = 4;
const OFF_ARG0_LO = 16;
const OFF_ARG0_HI = 20;
const OFF_ARG1_LO = 24;

// Audit architecture identifiers (<linux/audit.h>)
export const AUDIT_ARCH_X86_64 = 0xc000003e;
export const AUDIT_ARCH_AARCH64 = 0xc00000b7;
export const X32_SYSCALL_BIT = 0x40000000;

// Socket address families (<linux/socket.h>)
export const AF_UNIX = 1;
export const AF_INET = 2;
export const AF_INET6 = 10;
export const AF_NETLINK = 16;
export const AF_PACKET = 17;
export const AF_VSOCK = 40;

// Dangerous terminal ioctl request codes
export const TIOCSTI = 0x5412;
export const TIOCLINUX = 0x541c;

// CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET
export const CLONE_NEW_FLAGS_MASK = 0x7e020000;

// Seccomp verdicts (<linux/seccomp.h>)
export const SECCOMP_RET_KILL_PROCESS = 0x80000000;
export const SECCOMP_RET_ERRNO = 0x00050000;
export const SECCOMP_RET_ALLOW = 0x7fff0000;
export const EPERM = 1;
export const EACCES = 13;
export const ENOSYS = 38;

                               
                             
                              
                         
                          
                              
                         
                          
                                             
 

export const X86_64_SYSCALLS               = {
  auditArch: AUDIT_ARCH_X86_64,
  rejectX32: true,
  ioctl: 16,
  socket: 41,
  socketpair: 53,
  clone: 56,
  clone3: 435,
  deniedSyscalls: [
    101, // ptrace
    155, // pivot_root
    161, // chroot
    163, // acct
    165, // mount
    166, // umount2
    167, // swapon
    168, // swapoff
    169, // reboot
    175, // init_module
    176, // delete_module
    179, // quotactl
    246, // kexec_load
    248, // add_key
    249, // request_key
    250, // keyctl
    272, // unshare
    298, // perf_event_open
    308, // setns
    310, // process_vm_readv
    311, // process_vm_writev
    312, // kcmp
    313, // finit_module
    320, // kexec_file_load
    321, // bpf
    323, // userfaultfd
    425, // io_uring_setup
    426, // io_uring_enter
    427, // io_uring_register
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    442, // mount_setattr
    443, // quotactl_fd
  ],
};

export const AARCH64_SYSCALLS               = {
  auditArch: AUDIT_ARCH_AARCH64,
  rejectX32: false,
  ioctl: 29,
  socket: 198,
  socketpair: 199,
  clone: 220,
  clone3: 435,
  deniedSyscalls: [
    39,  // umount2
    40,  // mount
    41,  // pivot_root
    51,  // chroot
    60,  // quotactl
    89,  // acct
    97,  // unshare
    104, // kexec_load
    105, // init_module
    106, // delete_module
    117, // ptrace
    142, // reboot
    217, // add_key
    218, // request_key
    219, // keyctl
    224, // swapon
    225, // swapoff
    241, // perf_event_open
    268, // setns
    270, // process_vm_readv
    271, // process_vm_writev
    272, // kcmp
    273, // finit_module
    280, // bpf
    282, // userfaultfd
    294, // kexec_file_load
    425, // io_uring_setup
    426, // io_uring_enter
    427, // io_uring_register
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    442, // mount_setattr
    443, // quotactl_fd
  ],
};

                        
                        
                            
                            
                            
                     
 

class BpfAssembler {
                   items                                                                                = [];

  label(name        )       {
    this.items.push({ kind: 'label', name });
  }

  ldWordAbs(offset        )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_LD_W_ABS, k: offset } });
  }

  aluAnd(value        )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_ALU_AND_K, k: value >>> 0 } });
  }

  jeq(value        , jtLabel         , jfLabel         )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_JMP_JEQ_K, k: value >>> 0, jtLabel, jfLabel } });
  }

  jge(value        , jtLabel         , jfLabel         )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_JMP_JGE_K, k: value >>> 0, jtLabel, jfLabel } });
  }

  jmp(jaLabel        )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_JMP_JA, k: 0, jaLabel } });
  }

  ret(value        )       {
    this.items.push({ kind: 'inst', inst: { code: BPF_RET_K, k: value >>> 0 } });
  }

  assemble()         {
    const labels = new Map                ();
    const insts                 = [];

    for (const item of this.items) {
      if (item.kind === 'label') {
        if (labels.has(item.name)) {
          failSandbox('INVALID_SETUP', `Duplicate BPF label: ${item.name}`);
        }
        labels.set(item.name, insts.length);
      } else {
        insts.push(item.inst);
      }
    }

    const buf = Buffer.alloc(insts.length * 8);
    for (let i = 0; i < insts.length; i++) {
      const inst = insts[i] ;
      let jt = 0;
      let jf = 0;
      let k = inst.k;

      if (inst.jaLabel) {
        const target = labels.get(inst.jaLabel);
        if (target === undefined || target <= i) {
          failSandbox('INVALID_SETUP', `Invalid forward BPF JA label: ${inst.jaLabel}`);
        }
        k = (target - i - 1) >>> 0;
      } else {
        if (inst.jtLabel) {
          const target = labels.get(inst.jtLabel);
          if (target === undefined || target <= i || target - i - 1 > 255) {
            failSandbox('INVALID_SETUP', `Invalid BPF jt jump to ${inst.jtLabel} from ${i}`);
          }
          jt = target - i - 1;
        }
        if (inst.jfLabel) {
          const target = labels.get(inst.jfLabel);
          if (target === undefined || target <= i || target - i - 1 > 255) {
            failSandbox('INVALID_SETUP', `Invalid BPF jf jump to ${inst.jfLabel} from ${i}`);
          }
          jf = target - i - 1;
        }
      }

      const off = i * 8;
      buf.writeUInt16LE(inst.code, off);
      buf.writeUInt8(jt, off + 2);
      buf.writeUInt8(jf, off + 3);
      buf.writeUInt32LE(k >>> 0, off + 4);
    }

    return buf;
  }
}

                                        
                           
     
                                                                                
                                                                                      
                                                                                                   
     
                                        
     
                                                                                       
                                                                                            
                                                                               
     
                                      
 

export function compileSeccompBpf(options                       )         {
  const table = options.arch === 'aarch64' ? AARCH64_SYSCALLS : X86_64_SYSCALLS;
  const asm = new BpfAssembler();

  // 1. Validate architecture strictly (inline KILL right after check so jf never exceeds 255)
  asm.ldWordAbs(OFF_ARCH);
  asm.jeq(table.auditArch, 'arch_ok');
  asm.ret(SECCOMP_RET_KILL_PROCESS);
  asm.label('arch_ok');

  // 2. Load syscall number
  asm.ldWordAbs(OFF_NR);

  // 3. Block entire x32 ABI syscall range on x86_64
  if (table.rejectX32) {
    asm.jge(X32_SYSCALL_BIT, 'deny_eperm');
  }

  // 4. Inspect socket / socketpair domain argument
  asm.jeq(table.socket, 'check_socket');
  asm.jeq(table.socketpair, 'check_socket');

  // 5. Inspect ioctl request against TIOCSTI / TIOCLINUX
  asm.jeq(table.ioctl, 'check_ioctl');

  // 6. Optional user-namespace clone / clone3 defense when --disable-userns is unavailable
  if (options.blockUsernsClone) {
    asm.jeq(table.clone3, 'deny_enosys');
    asm.jeq(table.clone, 'check_clone');
  }

  // 7. Block dangerous syscalls unconditionally (io_uring, ptrace, mount, bpf, keyctl, ...)
  for (const nr of table.deniedSyscalls) {
    asm.jeq(nr, 'deny_eperm');
  }

  // 8. Default allow
  asm.jmp('allow');

  // Socket domain validation
  asm.label('check_socket');
  asm.ldWordAbs(OFF_ARG0_HI);
  asm.jeq(0, undefined, 'deny_eperm');
  asm.ldWordAbs(OFF_ARG0_LO);
  // Always block AF_VSOCK (WSL 2 Hyper-V/host escape channel) and AF_PACKET (raw packet sniffing)
  asm.jeq(AF_VSOCK, 'deny_eperm');
  asm.jeq(AF_PACKET, 'deny_eperm');
  // Allow AF_UNIX (UDS proxy & local IPC) and AF_NETLINK (isolated empty netns glibc compat)
  asm.jeq(AF_UNIX, 'allow');
  asm.jeq(AF_NETLINK, 'allow');
  if (options.blockNetworkSockets) {
    asm.jmp('deny_eacces');
  } else {
    // Allow only AF_INET / AF_INET6 inside isolated --unshare-net loopback bridge; reject exotic families
    asm.jeq(AF_INET, 'allow');
    asm.jeq(AF_INET6, 'allow');
    asm.jmp('deny_eacces');
  }

  // ioctl TIOCSTI / TIOCLINUX validation
  asm.label('check_ioctl');
  asm.ldWordAbs(OFF_ARG1_LO);
  asm.jeq(TIOCSTI, 'deny_eperm');
  asm.jeq(TIOCLINUX, 'deny_eperm');
  asm.jmp('allow');

  if (options.blockUsernsClone) {
    asm.label('check_clone');
    asm.ldWordAbs(OFF_ARG0_LO);
    asm.aluAnd(CLONE_NEW_FLAGS_MASK);
    asm.jeq(0, 'allow', 'deny_eperm');
  }

  asm.label('allow');
  asm.ret(SECCOMP_RET_ALLOW);

  asm.label('deny_eperm');
  asm.ret(SECCOMP_RET_ERRNO | EPERM);

  asm.label('deny_eacces');
  asm.ret(SECCOMP_RET_ERRNO | EACCES);

  if (options.blockUsernsClone) {
    asm.label('deny_enosys');
    asm.ret(SECCOMP_RET_ERRNO | ENOSYS);
  }

  return asm.assemble();
}
