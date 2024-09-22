import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import subprocess

#run this file while developing the app, it basically reruns the app each time u make an update in the app.py file
class ChangeHandler(FileSystemEventHandler):
    def __init__(self, script_name):
        self.script_name = script_name
        self.process = None
        self.run()

    def run(self):
        if self.process:
            self.process.terminate()
        self.process = subprocess.Popen([sys.executable, self.script_name])

    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            print(f'Changes detected: {event.src_path}')
            self.run()

if __name__ == "__main__":
    path = '.'  # Watch current directory
    event_handler = ChangeHandler('app.py')  # Replace with your script
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
