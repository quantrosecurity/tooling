"""vrl — a command-line client for the Vulnerability Research Labs CVE queue.

Submit a CVE for processing, watch it move through the pipeline, and read the
result. The CLI is a thin, read-mostly client over the public VRL API; it ships
nothing proprietary and talks only to the documented HTTP contract.
"""

__version__ = "0.1.0"
