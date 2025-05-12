#!/usr/bin/env python3
""" A python utility that will run tests repeatedly which can be used to catch flakes
"""

from dataclasses import dataclass


from pathlib import Path
import queue
import subprocess
import sys
from threading import Thread
from typing import List, Iterator
import os

import logging
import shutil

# Create a basic logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

NB_WORKERS = int(os.environ.get("NB_WORKERS", 5))
NB_JOBS = int(os.environ.get("NB_JOBS", 10))


@dataclass
class Job:
    """ A job represents a run of the integration tests.

    To ensure that multiple jobs don't interact we use a different
    TEST_DIRECTORY for each job.
    """
    job_id: str
    test_directory: Path
    command: List[str]

    def execute(self):
        new_env = dict(os.environ)
        new_env["TEST_DIRECTORY"] = self.test_directory

        os.makedirs(self.test_directory, exist_ok=True)

        stdout_path = self.test_directory.joinpath("stdout")
        stderr_path = self.test_directory.joinpath("stderr")
        with open(stdout_path, "w") as out_fh, open(stderr_path, "w") as err_fh:
            proc = subprocess.Popen(
                self.command,
                env=new_env,
                stdout=out_fh,
                stderr=err_fh,
            )
            proc.wait()

            if proc.returncode != 0:
                logger.warning("Test failed in job %s", self.job_id)
            else:
                # To save some disk space
                logger.debug("Successfully executed %s", self.job_id)
                shutil.rmtree(self.test_directory, ignore_errors=True)


@dataclass
class App:
    workers: List[str]
    job_queue: queue.Queue[Job]

    def __init__(self, num_workers, jobs: Iterator[Job]):
        self.workers = [f"worker_{iii}" for iii in range(0, num_workers)]
        self.job_queue = queue.Queue()
        for job in jobs:
            self.job_queue.put(job)

    def worker_thread(self, worker_id) -> Thread:
        """Creates and start a thread for a single worker"""

        def do_work(worker_id: str):
            logger.info("Launching worker %s", worker_id)
            while True:
                try:
                    job = self.job_queue.get(block=False)
                except queue.Empty:
                    logger.debug("Work completed: Shutting down %s", worker_id)
                    return

                logger.info("Executing job %s on worker %s", job.job_id, worker_id)
                job.execute()
            return

        t = Thread(target=do_work, name=worker_id, args=[worker_id])
        t.start()
        return t

    def run(self):
        """Run all jobs and wait for all workers to be completed"""
        ts = [self.worker_thread(w) for w in self.workers]

        # Join all threads
        for t in ts:
            t.join()

        logger.info("All work completed. Check ./flake_finder")


def create_jobs(num_jobs: int, command: List[str]) -> Iterator[Job]:
    """Create `num_jobs` that run the test-suite
    """
    for iii in range(0, num_jobs):
        yield Job(
            job_id=f"job_{iii:03}",
            test_directory=Path(f"./flake_finder/job_{iii:03d}"),
            command=command,

        )


if __name__ == "__main__":

    # Read command line arguments
    args = sys.argv
    script_name = args[0]
    other_args = args[1:]

    if other_args == []:
        print("Please specify a test. Eg:")
        print("python flake_finder.py just int")
        print("Will run all integration tests")
        exit(1)

    jobs = create_jobs(num_jobs=NB_JOBS, command=other_args)
    app = App(num_workers=NB_WORKERS, jobs=jobs)
    app.run()
