"""
Progress Reporting Utilities

Provides consistent progress reporting across all pipeline stages.
Supports both console output and callback-based reporting for integration.
"""

import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, List, Any
from datetime import datetime, timedelta


@dataclass
class ProgressStats:
    """Statistics for a progress operation."""
    operation: str
    total: int
    current: int = 0
    start_time: float = field(default_factory=time.time)
    errors: int = 0
    skipped: int = 0

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def percent(self) -> float:
        return (self.current / self.total * 100) if self.total > 0 else 0

    @property
    def rate(self) -> float:
        """Items per second."""
        return self.current / self.elapsed if self.elapsed > 0 else 0

    @property
    def eta_seconds(self) -> float:
        """Estimated seconds remaining."""
        if self.rate <= 0:
            return 0
        remaining = self.total - self.current
        return remaining / self.rate

    @property
    def eta_str(self) -> str:
        """Human-readable ETA."""
        eta = self.eta_seconds
        if eta <= 0:
            return "Done"
        elif eta < 60:
            return f"{eta:.0f}s"
        elif eta < 3600:
            return f"{eta/60:.1f}m"
        else:
            return f"{eta/3600:.1f}h"


class ProgressReporter:
    """
    Unified progress reporting with multiple output modes.

    Usage:
        reporter = ProgressReporter(verbose=True)

        with reporter.task("Analyzing functions", total=1000) as progress:
            for func in functions:
                # do work
                progress.advance()

        reporter.summary("Analysis complete", {"functions": 1000, "time": "5.2s"})
    """

    def __init__(self,
                 verbose: bool = False,
                 quiet: bool = False,
                 callback: Optional[Callable[[str, ProgressStats], None]] = None,
                 update_interval: float = 0.5):
        """
        Initialize reporter.

        Args:
            verbose: Show detailed per-item output
            quiet: Suppress all output except errors
            callback: Optional callback for progress events
            update_interval: Minimum seconds between progress bar updates
        """
        self.verbose = verbose
        self.quiet = quiet
        self.callback = callback
        self.update_interval = update_interval
        self._last_update = 0
        self._current_task: Optional[ProgressStats] = None

    def _emit(self, message: str, end: str = "\n", force: bool = False):
        """Write message to console."""
        if self.quiet and not force:
            return
        sys.stdout.write(message + end)
        sys.stdout.flush()

    def _should_update(self) -> bool:
        """Check if enough time has passed for an update."""
        now = time.time()
        if now - self._last_update >= self.update_interval:
            self._last_update = now
            return True
        return False

    def header(self, title: str, char: str = "="):
        """Print a section header."""
        if self.quiet:
            return
        width = 60
        self._emit("")
        self._emit(char * width)
        self._emit(f"  {title}")
        self._emit(char * width)

    def stage(self, name: str, description: str = ""):
        """Announce a new processing stage."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._emit(f"\n[{timestamp}] {name}")
        if description:
            self._emit(f"  {description}")

    def info(self, message: str):
        """Print an informational message."""
        self._emit(f"  {message}")

    def detail(self, message: str):
        """Print a detail (only in verbose mode)."""
        if self.verbose:
            self._emit(f"    {message}")

    def warning(self, message: str):
        """Print a warning message."""
        self._emit(f"  [!] WARNING: {message}", force=True)

    def error(self, message: str):
        """Print an error message."""
        self._emit(f"  [X] ERROR: {message}", force=True)

    def success(self, message: str):
        """Print a success message."""
        self._emit(f"  [OK] {message}")

    def task(self, operation: str, total: int) -> 'ProgressTask':
        """
        Create a progress task context manager.

        Usage:
            with reporter.task("Processing", total=100) as progress:
                for item in items:
                    progress.advance()
        """
        return ProgressTask(self, operation, total)

    def progress_bar(self, stats: ProgressStats, width: int = 30):
        """Render and display a progress bar."""
        if self.quiet:
            return

        if not self._should_update() and stats.current < stats.total:
            return

        filled = int(width * stats.current / stats.total) if stats.total > 0 else 0
        bar = "=" * filled + ">" * (1 if filled < width else 0) + " " * (width - filled - 1)

        line = f"\r  [{bar}] {stats.percent:5.1f}% ({stats.current:,}/{stats.total:,}) "
        line += f"ETA: {stats.eta_str}  "

        self._emit(line, end="")

        if stats.current >= stats.total:
            self._emit("")  # Newline when complete

        if self.callback:
            self.callback("progress", stats)

    def summary(self, title: str, stats: dict):
        """Print a summary block."""
        if self.quiet:
            return
        self._emit(f"\n  {title}:")
        for key, value in stats.items():
            if isinstance(value, float):
                self._emit(f"    {key}: {value:,.2f}")
            elif isinstance(value, int):
                self._emit(f"    {key}: {value:,}")
            else:
                self._emit(f"    {key}: {value}")

    def table(self, headers: List[str], rows: List[List[Any]], title: str = ""):
        """Print a formatted table."""
        if self.quiet:
            return

        if title:
            self._emit(f"\n  {title}:")

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        # Header
        header_line = "  " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        self._emit(header_line)
        self._emit("  " + "-+-".join("-" * w for w in widths))

        # Rows
        for row in rows:
            row_line = "  " + " | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
            self._emit(row_line)


class ProgressTask:
    """Context manager for tracking task progress."""

    def __init__(self, reporter: ProgressReporter, operation: str, total: int):
        self.reporter = reporter
        self.stats = ProgressStats(operation=operation, total=total)

    def __enter__(self) -> 'ProgressTask':
        self.reporter.info(f"{self.stats.operation}...")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            elapsed = self.stats.elapsed
            rate = self.stats.rate
            self.reporter.info(
                f"Completed {self.stats.current:,} items in {elapsed:.1f}s ({rate:.1f}/sec)"
            )
            if self.stats.errors > 0:
                self.reporter.warning(f"{self.stats.errors} errors occurred")
            if self.stats.skipped > 0:
                self.reporter.info(f"Skipped {self.stats.skipped} items")
        return False

    def advance(self, count: int = 1, error: bool = False, skip: bool = False):
        """Advance progress by count items."""
        self.stats.current += count
        if error:
            self.stats.errors += count
        if skip:
            self.stats.skipped += count
        self.reporter.progress_bar(self.stats)

    def set_current(self, value: int):
        """Set current progress to specific value."""
        self.stats.current = value
        self.reporter.progress_bar(self.stats)

    def log(self, message: str):
        """Log a detail message (verbose mode only)."""
        self.reporter.detail(message)


def format_size(size_bytes: int) -> str:
    """Format byte size as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


# Convenience function for quick progress iteration
def progress_iter(items, reporter: ProgressReporter, operation: str):
    """
    Iterate with progress reporting.

    Usage:
        for item in progress_iter(items, reporter, "Processing"):
            process(item)
    """
    items_list = list(items)
    with reporter.task(operation, len(items_list)) as progress:
        for item in items_list:
            yield item
            progress.advance()


if __name__ == "__main__":
    # Demo/test the progress reporting
    print("Testing ProgressReporter...")

    reporter = ProgressReporter(verbose=True)

    reporter.header("Progress Reporter Demo")

    reporter.stage("Stage 1", "Testing basic progress bar")

    with reporter.task("Processing items", total=100) as progress:
        for i in range(100):
            time.sleep(0.02)  # Simulate work
            progress.advance()
            if i == 50:
                progress.log("Halfway there!")

    reporter.stage("Stage 2", "Testing summary output")

    reporter.summary("Results", {
        "total_items": 100,
        "processed": 95,
        "errors": 5,
        "duration_seconds": 2.5
    })

    reporter.stage("Stage 3", "Testing table output")

    reporter.table(
        headers=["Version", "Functions", "Matched", "Confidence"],
        rows=[
            ["1.00", 2847, 2500, "87.8%"],
            ["1.09d", 3102, 2890, "93.2%"],
            ["1.13c", 3246, 3100, "95.5%"],
        ],
        title="Matching Results"
    )

    reporter.success("Demo complete!")
