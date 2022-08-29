from hashlib import sha256
import json
from optparse import OptionParser, OptionGroup
import os
from shutil import copyfile
import signal
import sys
import traceback

import pyptrace
from elftools.elf import elffile

PROGRAM_VERSION = '1.3.2'
PROGRAM_USAGE = 'Usage: %prog [options] <output_directory> <tracee_path> [tracee_args]...'

BREAKPOINTS = dict()

def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE,
                          version='%prog ' + PROGRAM_VERSION)
    parser.add_option('-u', '--uid', action='store', type='int', default=None,
            help='Run tracee with user ID UID (default: user\'s UID if using sudo, '
            'otherwise root\'s)')
    parser.add_option('-g', '--gid', action='store', type='int', default=None,
            help='Run tracee with group ID GID (default: user\'s GID if using sudo, '
            'otherwise root\'s)')
    parser.add_option('--collect', action='store_true', default=False,
            help='Disable Griffin and Collect PT traces')

    group_snapshot = OptionGroup(parser, 'Snapshot Arguments')
    group_snapshot.add_option('--concrete-argv', action='store_true', default=False,
            help='Make argv concrete in saved state')
    group_snapshot.add_option('--concrete-env', action='store_true', default=False,
            help='Make env concrete in saved state')
    group_snapshot.add_option('--concrete-fs', action='store_true', default=False,
            help='Make files in filesystem concrete')
    group_snapshot.add_option('--snapshot-rva', action='store', type='int', default=None,
            help="Override address to snapshot, relative to main object's base address")
    parser.add_option_group(group_snapshot)

    group_debug = OptionGroup(parser, 'Debug Arguments')
    group_debug.add_option('--time', action='store_true', default=False,
            help='Report runtime of tracee')
    group_debug.add_option('--no-trace', action='store_true', default=False,
            help='Skip recording a trace')
    group_debug.add_option('--no-state', action='store_true', default=False,
            help='Skip saving a state')
    parser.add_option_group(group_debug)

    parser.disable_interspersed_args()
    options, args = parser.parse_args()
    if len(args) < 2:
        parser.print_usage()
        sys.exit(1)
    return (options, args)

def sha256_file(filepath):
    """Returns a sha256 has of a file's contents. Returns None on error."""
    if not os.path.isfile(filepath):
        return None

    try:
        with open(filepath, 'rb') as ifile:
            return sha256(ifile.read()).hexdigest()
    except:
        return None

def waitpid(pid, options):
    """Wrapper for waitpid that returns True if the process exited."""
    _, status = os.waitpid(pid, options)
    return os.WIFEXITED(status)

def set_breakpoint(pid, addr):
    """Sets a breakpoint."""
    if not pid in BREAKPOINTS:
        BREAKPOINTS[pid] = dict()

    ret, data = pyptrace.peekdata(pid, addr)
    BREAKPOINTS[pid][addr] = data

    # place an int3 (0xcc) on the exact byte the caller specified
    mask = (1 << (8 * pyptrace.WORD_SIZE)) - 0x100
    trap = (data & mask) | 0xcc
    pyptrace.pokedata(pid, addr, trap)

def rm_breakpoint(pid, addr):
    """Removes a breakpoint."""
    if not pid in BREAKPOINTS or not addr in BREAKPOINTS[pid]:
        return

    pyptrace.pokedata(pid, addr, BREAKPOINTS[pid][addr])

    del BREAKPOINTS[pid][addr]

def is_breakpoint(pid, addr):
    """Checks if there's a breakpoint at the given address."""
    return pid in BREAKPOINTS and addr in BREAKPOINTS[pid]

def next_event(pid):
    """Continue running the PID until an event occurs.

    If next trap is triggered by a breakpoint, this method will automatically
    fix the RIP. If the process is currently paused on a trap, it will be
    safely resumed without removing the trap.

    Returns the current regs at the event or None of the process exited.
    """
    ret, regs = pyptrace.getregs(pid)
    if is_breakpoint(pid, regs.rip):
        old_rip = regs.rip
        rm_breakpoint(pid, regs.rip)
        pyptrace.singlestep(pid)
        if waitpid(pid, 0):
            return None
        set_breakpoint(pid, old_rip)

    pyptrace.cont(pid, 0)
    if waitpid(pid, 0):
        return None
    ret, regs = pyptrace.getregs(pid)
    if is_breakpoint(pid, regs.rip - 1):
        regs.rip -= 1
        pyptrace.setregs(pid, regs)

    return regs

def get_virtual_entrypoint(pid, bin_path, entry):
    """Returns the virtual entrypoint, corrected for the actual
    loaded address of the process. If the ELF file is DYN, this will adjust
    the provided entry by the base of the loaded image. If the ELF file is
    EXEC, it will validate that the entry falls in the expected range from the
    maps file. The entry is either provided by the user or the entrypoint is
    read from the ELF file.

    pid -- The PID of the running process.
    bin_path -- The path of the binary to find in the target process.
    entry -- The optional user-provided offset to break on.

    Returns the address to break on.
    """
    va_bounds = get_object_va(pid, bin_path)
    if va_bounds is None:
        raise ValueError('Unable to find map of pid {}'.format(pid))
    va_start, va_end = va_bounds

    with open(bin_path, 'rb') as ifile:
        parsed_elf = elffile.ELFFile(ifile)
        elf_type = parsed_elf.header.e_type
        if entry is None:
            entry = parsed_elf.header.e_entry

        if elf_type == 'ET_DYN':
            return entry + va_start
        elif elf_type == 'ET_EXEC':
            if entry < va_start or entry >= va_end:
                raise ValueError(
                        'Entry address of non-PIE ELF did '
                        'not match found memory map'
                )
            return entry
        else:
            raise ValueError('Unhandled ELF type {}'.format(elf_type))

def get_object_va(pid, bin_path):
    """Returns the VA range of an object's *first* segment loaded into a
    running process.

    pid -- The PID of the running process.
    bin_path -- The path of the binary to find in the target process.

    Returns a tuple (va_start, va_end), or None if it cannot be found.
    """
    bin_path = os.path.abspath(bin_path)
    with open('/proc/%d/maps' % pid, 'r') as ifile:
        for row in ifile:
            if bin_path in row:
                va_start, va_end = row.split(' ')[0].split('-', 1)
                return int(va_start, 16), int(va_end, 16)
    return None

def attach(tracee, tracee_args, output_dir, options):
    """Create and attach to the tracee. Upon returning, the tracee will be paused
    at its entry point.

    Returns:
    Tracee's PID or 0 if there was an error.
    """
    # if the user didn't specify a uid/gid but sudo is being used, get the user's
    # IDs via the sudo environment variables
    if options.uid is None and 'SUDO_UID' in os.environ:
        options.uid = int(os.environ['SUDO_UID'])
    if options.gid is None and 'SUDO_GID' in os.environ:
        options.gid = int(os.environ['SUDO_GID'])

    # dump environment and configure GRIFFIN
    if not options.no_state:
        dump_state(output_dir, tracee_args, not options.concrete_argv, not options.concrete_env)
    if not options.no_trace:
        enable_griffin(os.path.basename(tracee))
    dump_files(output_dir, tracee_args, not options.concrete_fs)

    pid = os.fork()
    if pid == 0:  # within tracee
        # if options.gid: os.setgid(options.gid)
        # if options.uid: os.setuid(options.uid)
        os.setgid(0)
        os.setuid(0)
        pyptrace.traceme()
        
        # FIXME: hard code for postgresql
        tracee_args[0] = tracee

        print(tracee, tracee_args)
        ret = os.execv(tracee, tracee_args)
        sys.stderr.write("Failed to execv\n")
        sys.exit(ret)
    elif pid > 0:  # within tracer
        os.waitpid(pid, 0)
        options.snapshot_rva = get_virtual_entrypoint(pid, tracee, options.snapshot_rva)
        set_breakpoint(pid, options.snapshot_rva)
        if next_event(pid) is None:
            sys.stderr.write("Tracee exited before reaching entry point\n")
            return 0
        rm_breakpoint(pid, options.snapshot_rva)
        return pid
    else:  # fork failed
        sys.stderr.write("Failed to fork\n")
        sys.exit(1)

def enable_griffin(prog_name):
    """Sets up GRIFFIN to trace prog_name."""
    if os.path.exists('/tmp/tracer.lock'):
        sys.stderr.write("/tmp/tracer.lock exists, is someone already tracing?\n")
        sys.exit(2)
    open('/tmp/tracer.lock', 'w').close()
    with open('/proc/sys/vm/drop_caches', 'wb') as ifile:
        ifile.write(b"3\n")
    with open('/sys/kernel/debug/pt_monitor', 'w') as ifile:
        ifile.write(prog_name)

def disable_griffin(dir):
    """Disables GRIFFIN and copies/gzips trace to dir/trace.griffin.gz"""
    trace_path = os.path.join(dir, 'trace.file')
    with open('/var/log/pt.log', 'rb') as ifile:
        # with gzip.open(trace_path, 'wb') as ofile:
        with open(trace_path, 'wb') as ofile:
            ofile.write(ifile.read())
    
    trace_path = os.path.join(dir, 'trace.memory')
    with open('/sys/kernel/debug/pt_memory', 'rb') as ifile:
        with open(trace_path, 'wb') as ofile:
            ofile.write(ifile.read())

    with open('/sys/kernel/debug/pt_monitor', 'wb') as ifile:
        ifile.write(b"\x00")
        
    if os.path.exists('/tmp/tracer.lock'):
        os.remove('/tmp/tracer.lock')

def dump_state(dir, args, sym_argv=False, sym_env=False):
    """Creates dir/state.json formatted for use by analysis.py."""
    state_path = os.path.join(dir, 'state.json')
    state = dict()
    # argv
    state['argv'] = list()
    for arg in args:
        if not sym_argv:
            state['argv'].append({"type": "str", "value": arg})
        else:
            state['argv'].append({"type": "BVS", "value": len(arg) * 8})
    # env
    state['env'] = list()
    for key in os.environ:
        val = os.environ[key]
        if not sym_env:
            state['env'].append({"key_type": "str", "key_val": key, "key_size": None,
                                 "val_type": "str", "val_val": val, "val_size": None})
        else:
            state['env'].append({"key_type": "BVS", "key_val": "env", "key_size": len(key) * 8,
                                 "val_type": "BVS", "val_val": "env", "val_size": len(val) * 8})

    with open(state_path, 'w') as ofile:
        json.dump(state, ofile)

def dump_regs(output_dir, pid):
    """Dumps the registers for pid in JSON format to dir/regs.json."""
    regs_path = os.path.join(output_dir, 'regs.json')
    ret, regs = pyptrace.getregs(pid)

    reg_names = [attr for attr in dir(regs) if not attr.startswith('_')]
    reg_dict = {reg_name: getattr(regs, reg_name).real for reg_name in reg_names}

    del reg_dict['orig_rax']  # we don't need it

    with open(regs_path, 'w') as ofile:
        json.dump(reg_dict, ofile)

def dump_mem(dir, pid, main_bin, blobs_dir=None):
    """Dumps the memory for pid into a set of files in dir.

    blobs_dir is an optional parameter that may point to a directory for placing
    binary blobs in. When used, dumped objects will be symlinked against this
    directory of blobs. Use this when taking multiple snapshots with lots of redundant
    data to save storage space.

    dump_mem attempts to create blobs_dir if it doesn't exist.

    Keyword Arguments:
    dir -- The directory to dump the memory into.
    pid -- The PID to dump from.
    main_bin -- The absolute path of the main object executable.
    blobs_dir -- An optional directory to place binary blobs.
    """
    memdir = os.path.join(dir, 'mem/')
    bindir = os.path.join(dir, 'bin/')
    misc = os.path.join(dir, 'misc.json')
    misc_json = dict()
    fetched_bins = list()

    if not os.path.exists(memdir):
        os.mkdir(memdir)
    if not os.path.exists(bindir):
        os.mkdir(bindir)
    if not blobs_dir is None and not os.path.exists(blobs_dir):
        os.mkdir(blobs_dir)

    with open('/proc/%d/maps' % pid, 'r') as ifile:
        mem_fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
        for row in ifile:
            va_start, va_end = [int(va, 16) for va in row.split(' ', 1)[0].split('-')]
            if not 0 < (va_end - va_start) < 0x80000000:
                continue  # too big, skip
            full_name = row.strip().split(' ')[-1]
            name = os.path.basename(full_name)
            if va_start >= 0xf000000000000000:
                continue  # [vsyscall]
            if name == '[vvar]':
                continue  # [vvar] cannot be read

            # dump memory segment
            ofilepath = os.path.join(memdir, "%x-%s.bin" % (va_start, name))
            os.lseek(mem_fd, va_start, os.SEEK_SET)
            raw_mem = os.read(mem_fd, va_end - va_start)

            if not blobs_dir is None:
                # place blob in the blobs dir and symlink to it to save space
                blob_hash = sha256(raw_mem).hexdigest()
                blob_path = os.path.join(blobs_dir, blob_hash)
                if not os.path.exists(blob_path):
                    with open(blob_path, 'wb') as ofile:
                        ofile.write(raw_mem)

                # use relative path for portability
                orelpath = os.path.relpath(blob_path, memdir)
                os.symlink(orelpath, ofilepath)
            else:
                # no blobs dir, just write directly
                with open(ofilepath, 'wb') as ofile:
                    ofile.write(raw_mem)

            # fetch binary if segment was mapped from file
            if os.path.isfile(full_name) and not full_name in fetched_bins:
                binfn = "%x-%s" % (va_start, name)
                binfp = os.path.join(bindir, binfn)

                if not blobs_dir is None:
                    # again, use blobs dir to save space
                    with open(full_name, 'rb') as ifile:
                        blob_hash = sha256(ifile.read()).hexdigest()
                        blob_path = os.path.join(blobs_dir, blob_hash)
                        if not os.path.exists(blob_path):
                            copyfile(full_name, blob_path)

                        orelpath = os.path.relpath(blob_path, bindir)
                        os.symlink(orelpath, binfp)
                else:
                    copyfile(full_name, binfp)

                fetched_bins.append(full_name)

                # record which bin is main in misc.json
                if full_name == os.path.abspath(main_bin):
                    misc_json['main'] = binfn

        os.close(mem_fd)

    # additional important information
    misc_json['brk'] = get_tracee_brk(pid)
    with open(os.path.join(dir, 'misc.json'), 'w') as ofile:
        json.dump(misc_json, ofile)

def dump_files(outdir, tracee_args, symbolic_files=False):
    """Save copies of files touched by the tracee.

    Currently, this just checks each argv to see if it's a valid filepath.
    """
    files_json = {'files': {}, 'cwd': None}
    files_dir = os.path.join(outdir, 'files')

    if not os.path.exists(files_dir):
        os.mkdir(files_dir)

    # record cwd
    files_json['cwd'] = os.getcwd()

    # check tracee's argv for any valid filepaths
    for arg in tracee_args:
        if os.path.isfile(arg):
            shasum = sha256_file(arg)
            dest = os.path.join(files_dir, shasum)
            if not os.path.exists(dest):
                copyfile(arg, dest)
            files_json['files'][os.path.abspath(arg)] = {'data': os.path.join('files/', shasum),
                                                         'symbolic': symbolic_files}

        # We do not handle directories because they can be very deep,
        # have symlinks pointing outside the directory, etc. It's also
        # possible to use syscall hooking to collect only the files
        # touched by the tracee, but this incurs overhead and requires
        # the tracer to be attached at all times. Staying attached is
        # inevitable in some advanced modes (API snapshot), but we want
        # to keep the default mode as simple and hands-off as possible.

    # write files.json
    with open(os.path.join(outdir, 'files.json'), 'w') as ofile:
        json.dump(files_json, ofile)

def get_tracee_brk(pid):
    """Get the tracee's current brk."""
    # make backup of tracee's current regs and next code
    ret, orig_regs = pyptrace.getregs(pid)
    code_addr = orig_regs.rip
    ret, orig_word = pyptrace.peekdata(pid, code_addr)

    # setup a brk(0) syscall
    pyptrace.pokedata(pid, code_addr, 0x50f)  # syscall
    ret, new_regs = pyptrace.getregs(pid)
    new_regs.rax = 12
    new_regs.rdi = 0
    pyptrace.setregs(pid, new_regs)

    # do syscall and get result
    pyptrace.singlestep(pid)
    if waitpid(pid, 0):
        raise Exception("Something unexpected happened while getting brk")
    ret, new_regs = pyptrace.getregs(pid)
    curr_brk = new_regs.rax

    # revert tracee back to prior state
    pyptrace.pokedata(pid, code_addr, orig_word)
    pyptrace.setregs(pid, orig_regs)

    return curr_brk

def resolve_path(name):
    """Tries to find name in PATH.

    Returns empty string if no match is found.
    """
    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, name)
        if os.path.isfile(candidate):
            return candidate

    return ''

def main():
    """The main method."""
    options, args = parse_args()
    output_dir = args[0]
    tracee_path = args[1]

    # import IPython; IPython.embed()
    if options.collect == True:
        disable_griffin(output_dir)
        return

    if os.getuid() != 0:
        sys.stderr.write("This program must run as root\n")
        sys.exit(1)

    if not os.path.exists(tracee_path):
        # user may have provided a program name in PATH
        tracee_path = resolve_path(tracee_path)

    if not os.path.isfile(tracee_path):
        sys.stderr.write("%s is not a file\n" % tracee_path)
        sys.exit(1)

    # realpath() dereferences symlinks that would otherwise confuse enable_griffin()
    tracee_path = os.path.realpath(tracee_path)
    tracee_args = [os.path.basename(tracee_path)] + args[2:]

    if not os.path.exists(output_dir):
        try:
            os.mkdir(output_dir)
        except Exception as ex:
            sys.stderr.write("Failed to make %s: %s\n" % (output_dir, str(ex)))
            sys.exit(1)
    if not os.path.isdir(output_dir):
        sys.stderr.write("%s is not a directory\n" % output_dir)
        sys.exit(1)

    tracee_pid = 0
    try:
        tracee_pid = attach(tracee_path, tracee_args, output_dir, options)
    except:
        sys.stderr.write("**ERROR OCCURRED IN TRACER\n")
        sys.stderr.write("%s\n" % str(traceback.format_exc()))
        if tracee_pid > 0:
            try:
                os.kill(tracee_pid, signal.SIGKILL)
            except OSError:
                pass

if __name__ == '__main__':
    main()
