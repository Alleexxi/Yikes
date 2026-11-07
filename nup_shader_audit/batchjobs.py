"""Scan and audit several NUPs at once, each game in its own process.

Parsing is single-threaded Python, so threads cannot use more cores; separate processes can.
Every game's progress goes to its own log file instead of sharing the terminal, and each worker
process handles exactly one game so its memory is returned when the game finishes.
"""

import concurrent.futures
import contextlib
import multiprocessing
import os
import sqlite3
import struct
import sys
import time
from pathlib import Path

from .container.format import NupError


def peak_memory_mb():
    """This process's peak working set in MiB (Windows), else its peak resident size."""
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                        ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return round(counters.PeakWorkingSetSize / 1048576)
        return None
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    except (ImportError, OSError):
        return None


def work(job):
    """Scan and audit one NUP; never raises for an ordinary per-game failure."""
    # Imported here: cli imports this module, and a spawned worker imports it first.
    from .audit import audit
    from .cli import scan_input
    started = time.monotonic()
    log = Path(job['log'])
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, 'w', encoding='utf-8', errors='replace', buffering=1) as stream:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            try:
                output = scan_input(job['nup'], job['output'], resume=job['resume'],
                                    checkpoint_every=job['checkpoint_every'], workers=job['workers'],
                                    export_native=job['export_native'])
                report, directory = audit(output, job['emulator'], allow_incomplete=job['allow_incomplete'])
                result = {'status': 'completed', 'rejected': report['counts'].get('rejected', 0),
                          'total': report['total'],
                          'coverage_complete_for_recognized_formats':
                              report['coverage_complete_for_recognized_formats'],
                          'report_directory': directory}
            except (ValueError, OSError, NupError, sqlite3.Error, struct.error, RuntimeError) as exc:
                print(f'FAILED: {exc}', file=sys.stderr, flush=True)
                result = {'status': 'error', 'error': str(exc)}
    result['seconds'] = round(time.monotonic() - started, 1)
    result['peak_working_set_mb'] = peak_memory_mb()
    return result


def run_parallel(job_count, jobs, finished):
    """Run `jobs` ((index, job dict) pairs, in submission order) on `job_count` processes.

    `finished(index, result)` is called in the parent as each game completes. A worker that
    dies (for example out of memory) is reported as an error for its game.
    """
    context = multiprocessing.get_context('spawn')
    pool = concurrent.futures.ProcessPoolExecutor(max_workers=job_count, mp_context=context,
                                                  max_tasks_per_child=1)
    try:
        futures = {pool.submit(work, job): index for index, job in jobs}
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                result = future.result()
            except concurrent.futures.process.BrokenProcessPool as exc:
                result = {'status': 'error', 'error': f'Worker process died ({exc}); '
                                                      'likely out of memory - use fewer --jobs'}
            except Exception as exc:  # A bug in one game must not hide the others' results.
                result = {'status': 'error', 'error': f'{type(exc).__name__}: {exc}'}
            finished(index, result)
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown()
