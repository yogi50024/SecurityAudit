"""
Scan Scheduler

Schedules regular scans using the `schedule` library.
"""

import schedule
import time
import subprocess
import logging

def run_audit():
    logging.info("Starting scheduled audit...")
    result = subprocess.run(["python", "run_audit.py"])
    if result.returncode == 10:
        logging.error("Security audit failed! Findings above threshold detected.")
    else:
        logging.info("Security audit passed.")

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Schedule the audit to run once a day at midnight
    schedule.every().day.at("00:00").do(run_audit)
    # You can add more schedules if needed:
    # schedule.every().hour.do(run_audit)

    logging.info("Scheduler started. Waiting for jobs...")
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()
