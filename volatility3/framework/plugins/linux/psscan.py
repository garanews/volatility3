# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# RPi Zero 2W patch: scan fisico per task_struct usando pid+comm
import logging
import struct
import re
from typing import Iterable, List, Tuple
from enum import Enum

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

PID_OFFSET   = 0x588
TGID_OFFSET  = 0x58c
COMM_OFFSET  = 0x770
TASKS_OFFSET = 0x4b8
PAGE_OFFSET_VMALLOC = 0xffffff8000000000

# Regex per comm validi: almeno 3 char, alfanumerici + /:-_.[]@
COMM_RE = re.compile(rb'^[a-zA-Z0-9_\-./:\[\]@ ]{3,15}$')

class DescExitStateEnum(Enum):
    TASK_RUNNING = 0x00000000
    EXIT_DEAD    = 0x00000010
    EXIT_ZOMBIE  = 0x00000020
    EXIT_TRACE   = EXIT_ZOMBIE | EXIT_DEAD


def _is_valid_comm(comm_bytes: bytes) -> bool:
    """Filtra comm plausibili per processi Linux reali."""
    if len(comm_bytes) < 3:
        return False
    if not COMM_RE.match(comm_bytes):
        return False
    # Escludi pattern tipici di falsi positivi
    # (sezioni ELF, stringhe C, pattern kernel non-process)
    fp_patterns = [
        b'_state', b'_free', b'mount', b'_remove', b'_create',
        b'.symtab', b'.strtab', b'.rodata', b'.text', b'.plt',
        b'_sched_', b'syscall', b'mpoline', b'__param',
        b'720x480', b'crtc_sta', b'drm', b'ion_usec',
        b'vblankof', b'v_free', b'_newsel', b'_llseek',
    ]
    for fp in fp_patterns:
        if fp in comm_bytes:
            return False
    return True


class PsScan(interfaces.plugins.PluginInterface):
    """Scans for processes present in a particular linux image (RPi AArch64)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"],
            ),
        ]

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]

        for task in self.scan_tasks(
            self.context, vmlinux_module_name, vmlinux.layer_name
        ):
            try:
                pid  = task.tgid
                tid  = task.pid
                ppid = 0
                try:
                    ppid = task.parent.tgid
                except Exception:
                    pass
                name = utility.array_to_string(task.comm)
                try:
                    exit_state = DescExitStateEnum(task.exit_state).name
                except ValueError:
                    exit_state = "UNKNOWN"
                yield (0, (format_hints.Hex(task.vol.offset), pid, tid, ppid, name, exit_state))
            except Exception:
                continue

    @classmethod
    def scan_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        kernel_layer_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        vmlinux = context.modules[vmlinux_module_name]
        kernel_layer = context.layers[kernel_layer_name]

        if not kernel_layer.dependencies:
            raise exceptions.LayerException(kernel_layer_name, "No dependencies")
        memory_layer_name = kernel_layer.dependencies[0]
        memory_layer = context.layers[memory_layer_name]

        vollog.info(f"RPi psscan v2: scanning {memory_layer_name}")

        seen_phys = set()
        chunk_size = 4 * 1024 * 1024

        phys = memory_layer.minimum_address
        max_phys = memory_layer.maximum_address

        while phys < max_phys:
            try:
                chunk = context.layers.read(
                    memory_layer_name, phys,
                    min(chunk_size, max_phys - phys), pad=True
                )
            except Exception:
                phys += chunk_size
                continue

            for i in range(0, len(chunk) - COMM_OFFSET - 20, 8):
                if i + COMM_OFFSET + 16 > len(chunk):
                    break

                pid_val  = struct.unpack_from('<I', chunk, i + PID_OFFSET)[0]
                tgid_val = struct.unpack_from('<I', chunk, i + TGID_OFFSET)[0]

                # pid deve essere plausibile
                if not (1 <= pid_val <= 65534):
                    continue
                # tgid deve essere uguale a pid (thread leader) o plausibile
                if tgid_val != pid_val:
                    if not (1 <= tgid_val <= 65534):
                        continue
                    # tgid > pid non ha senso per un leader
                    if tgid_val > pid_val + 100:
                        continue

                comm_bytes = chunk[i + COMM_OFFSET: i + COMM_OFFSET + 16]
                comm_end = comm_bytes.find(b'\x00')
                if comm_end < 3:
                    continue
                comm_str = comm_bytes[:comm_end]

                if not _is_valid_comm(comm_str):
                    continue

                task_phys = phys + i
                if task_phys in seen_phys:
                    continue
                seen_phys.add(task_phys)

                task_va = task_phys + PAGE_OFFSET_VMALLOC

                try:
                    ptask = context.object(
                        vmlinux.symbol_table_name + constants.BANG + "task_struct",
                        offset=task_va,
                        layer_name=kernel_layer_name,
                        native_layer_name=kernel_layer_name,
                    )
                    yield ptask
                except Exception:
                    continue

            phys += chunk_size

    def run(self):
        columns = [
            ("OFFSET (V)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
            ("EXIT_STATE", str),
        ]
        return renderers.TreeGrid(columns, self._generator())