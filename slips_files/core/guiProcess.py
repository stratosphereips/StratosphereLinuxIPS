# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

import multiprocessing
import traceback
from slips_files.common.slips_utils import utils
import os

# Gui Process
class GuiProcess(multiprocessing.Process):
    """
    The Gui process is only meant to start the Kalipso interface
    """

    def __init__(self):
        self.name = 'GUI'
        multiprocessing.Process.__init__(self)

    def main(self):
        os.system(f'cd modules/kalipso;node kalipso.js -p {self.redis_port}')
