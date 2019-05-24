from multiprocessing import Process
import sys
import time


class ProgressBar:
    def __init__(self, bar_size: int, prefix: str, wait_time: float =0.25):
        self.bar_size = bar_size
        self.prefix = prefix
        self.file = sys.stdout
        self.proc = None
        self.wait_time = wait_time

    def start_progress_bar(self):
        self.proc = Process(target=self.progress_bar)
        self.proc.start()

    def stop_progress_bar(self, final_word: str = ' -> Done.'):
        self.proc.terminate()
        # Print final value in the bar.
        s = ''
        for i in range(self.bar_size):
            s += '#'
        self.file.write("\r" + self.prefix + '[' + s + ']' + final_word)
        self.file.flush()
        self.file.write('\n')

    def refresh_bar(self, j, size, prefix, file):
        x = int(size * j / size)
        s = ''
        for i in range(size):
            if i == x or i + 1 % size == x or i - 1 % size == x:
                temp = '#'
            else:
                temp = ' '
            s += temp
        file.write("%s[%s]\r" % (prefix, s))
        file.flush()

    def progress_bar(self):
        index = 0
        while True:
            i = index % self.bar_size
            self.refresh_bar(i, self.bar_size, self.prefix, self.file)
            time.sleep(self.wait_time)
            index += 1
