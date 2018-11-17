import multiprocessing
import globaldata
import sys
import curses
import curses.panel
from datetime import datetime
from datetime import timedelta
import select
from string import Template


# Curses output Process
class CursesProcess(multiprocessing.Process):
    """ A class to output data in a curses interface """
    def __init__(self, inputqueue, verbose, debug, config ):
        multiprocessing.Process.__init__(self)
        self.queue = inputqueue
        self.verbose = verbose
        self.debug = debug
        self.config = config

    def run(self):
        try:
            self.ui = ui()
            self.ui.update_status('Detecting...')
            while True:
                #self.ui.update_hour()
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        self.ui.update_status('Receiving something')
                        for substr in line.split('\n'):
                            self.ui.update_histogram(substr)
                    else:
                        # Here we should still print the lines coming in the input for a while after receiving a 'stop'. We don't know how to do it.
                        self.queue.put('stop')
                        return True
                elif self.queue.empty():
                    self.ui.update_status('checking queue')
                    # Manage the online keys
                    """
                    while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        self.ui.update_hour()
                        char = sys.stdin.read(1)
                        # This reading of letters is NOT working. Maybe because of the processing thread????
                        if char.strip() == "q":
                            self.ui.update_status('quitt')
                            self.ui.quit_ui()
                            # Send the signal back that we are stopping
                            self.queue.put('stop')
                            break
                    """
                    self.ui.refresh()
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            print('\tProblem with CursesProcess()')
            print(type(inst))
            print(inst.args)
            print(inst)
            sys.exit(1)

class ui:
    """ This is the class to manage the curses ui """
    def __init__(self):
        # Setup the curses
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)
        # Get the size of the screen
        self.curr_height, self.curr_width = self.stdscr.getmaxyx()
        # ???
        self.stdscr.keypad(1)
        self.hist_lines = []
        # Window 1. Main. A little bit smaller that the screen. Use this as maximum values
        self.w1height = self.curr_height - 5
        self.w1width = self.curr_width

        # curses.newwin(DOWN RIGHT CORNER y from top, DOWN RIGHT CORNER x from left , TOP LEFT CORNER y from top , TOP LEFT CORNER x from left)
        # 0 means the size of the current window
        self.win1 = curses.newwin(self.w1height, self.w1width, 0, 0)
        self.win1.border(0)
        # Create new panel, as large as win1
        self.pan1 = curses.panel.new_panel(self.win1)
        # Create the win2, status window
        self.win2 = curses.newwin(0, 0, self.w1height, 0)
        self.win2.border(0)
        # Create new panel, as large as win2
        self.pan2 = curses.panel.new_panel(self.win2)
        # Title
        self.win1.addstr(1, 1, "Stratosphere Linux IPS", curses.color_pair(4))
        self.update_status('Receiving data...')
        self.win2.addstr(2, 1, "Press 'q' to quit.", curses.color_pair(4))
        # Hide pan1, for some reason
        self.pan1.hide()
        self.refresh()

    def refresh(self):
        curses.panel.update_panels()
        self.win1.refresh()
        self.win2.refresh()

    def update_status(self, text):
        text = str(text)
        status = '{:15.15}'.format(text)
        self.win2.addstr(1, 1, "Status: {}".format(status), curses.color_pair(2))
        self.refresh()

    def update_hour(self):
        self.win2.addstr(3, self.w1width - 45, 'Current Time: ' + str(datetime.now()), curses.color_pair(9))
        self.refresh()

    def update_histogram(self, text):
        """
        Put one more line in the histogram
        """
        # Create a string line that has at the end empty spaces. The amount of empty spaces vary dynamically with the size of the screen
        templ_string = '{:$size}'
        # I don't know why 8 works. Less than that and part of the screen is deleted
        templ_string1 = Template(templ_string).substitute(size=self.w1width - 8)
        newtext = templ_string1.format(text)

        self.hist_lines.append(newtext)
        # Redraw the complete histogram, from bottom up
        for lpos in range(self.w1height - 2, 2, -1):
            try:
                # -1 is to start from the last line
                # - so we go down the list
                # height of the window - 2 (2 for the line border around the win)
                #self.win1.addstr(lpos, 1, str(self.hist_lines[-1 - (self.w1height - 2 - lpos)])[:self.w1width - 2], curses.color_pair(7))
                # These -2 both in height and width are because of the linex in the border of the windows. The windows are a little smaller
                # The self.w1width - 2 is to limit the text to the max amount of screen available
                linetoput = str(self.hist_lines[-1 - (self.w1height - 2 - lpos)])[:self.w1width - 2]
                self.win1.addstr(lpos, 1, linetoput, curses.color_pair(7))
            except IndexError:
                pass
            self.refresh()

    def quit_ui(self):
        curses.nocbreak()
        self.stdscr.keypad(0)
        curses.curs_set(1)
        curses.echo()
        curses.endwin()
