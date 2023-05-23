# pyOCD debugger
# Copyright (c) 2023 PyOCD Authors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from time import sleep

from ...core import exceptions
from ...flash.eraser import FlashEraser
from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile
from ...utility.timeout import Timeout


FMC_KEY    = 0x40022004
FMC_OBKEY  = 0x40022008
FMC_STAT   = 0x4002200C
FMC_CTL    = 0x40022010
FMC_OBSTAT = 0x4002201C

OBPG  = (1 << 4)
OBER  = (1 << 5)
START = (1 << 6)
OBWEN = (1 << 9)

BUSY = (1 << 0)

KEY1 = 0x45670123
KEY2 = 0xCDEF89AB

FLASH_ERASE_TIMEOUT = 10.0

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xb086b5b0, 0x460c4613, 0x90054605, 0x92039104, 0x49129805, 0x49124008, 0x5050464a, 0xf2484811,
    0x60010100, 0x49114810, 0x49116001, 0x48116001, 0x21046800, 0x93024208, 0x95009401, 0xe7ffd10a,
    0x490e480d, 0x480e6001, 0x60012106, 0x490e480d, 0xe7ff6001, 0xb0062000, 0x46c0bdb0, 0xfffe0000,
    0x00000004, 0x40022000, 0x40022004, 0x45670123, 0xcdef89ab, 0x4002201c, 0x40003000, 0x00005555,
    0x40003004, 0x40003008, 0x00000fff, 0x4601b082, 0x48049001, 0x23806802, 0x6002431a, 0x91002000,
    0x4770b002, 0x40022010, 0x6801480d, 0x43112204, 0x68016001, 0x43112240, 0xe7ff6001, 0x68004809,
    0x42082101, 0xe7ffd004, 0x49084807, 0xe7f56001, 0x68014803, 0x43912204, 0x20006001, 0x46c04770,
    0x40022010, 0x4002200c, 0x40003000, 0x0000aaaa, 0x4601b082, 0x48109001, 0x23026802, 0x6002431a,
    0x4b0e9a01, 0x6802601a, 0x431a2340, 0x91006002, 0x480be7ff, 0x21016800, 0xd0044208, 0x4809e7ff,
    0x60014909, 0x4804e7f5, 0x22026801, 0x60014391, 0xb0022000, 0x46c04770, 0x40022010, 0x40022014,
    0x4002200c, 0x40003000, 0x0000aaaa, 0xb08ab5b0, 0x460c4613, 0x90084605, 0x92069107, 0x90042000,
    0x99079806, 0x90031840, 0x7800a807, 0x28000740, 0x94019302, 0xd0079500, 0x9807e7ff, 0x40082107,
    0x1a082108, 0xe7ff9004, 0x90052000, 0x9805e7ff, 0x42889904, 0xe7ffd20a, 0x1c419803, 0x21ff9103,
    0xe7ff7001, 0x1c409805, 0xe7f09005, 0x1dc09807, 0x43882107, 0x98089007, 0x464a4923, 0x22015851,
    0x18890452, 0xd2384288, 0xe7ffe7ff, 0x28009807, 0xe7ffd032, 0x6801481d, 0x43112201, 0x98066001,
    0x99086800, 0x98066008, 0x99086840, 0xe7ff6048, 0x68004817, 0x42082101, 0xe7ffd001, 0x4813e7f8,
    0x22016801, 0x60014391, 0x68004811, 0x42082114, 0xe7ffd008, 0x6801480e, 0x43112214, 0x20016001,
    0xe00d9009, 0x30089808, 0x98069008, 0x90063008, 0x38089807, 0xe7c99007, 0x2000e7ff, 0xe7ff9009,
    0xb00a9809, 0x46c0bdb0, 0x00000004, 0x40022010, 0x4002200c, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000091,
    'pc_program_page': 0x20000151,
    'pc_erase_sector': 0x200000f5,
    'pc_eraseAll': 0x200000ad,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000254,
    'begin_stack' : 0x20001a60,
    'end_stack' : 0x20000a60,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000260,
        0x20000660
    ],
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x254,
    'rw_start': 0x258,
    'rw_size': 0x4,
    'zi_start': 0x25c,
    'zi_size': 0x4,

    # Flash information
    'flash_start': 0x8000000,
    'flash_size': 0x10000,
    'sector_sizes': (
        (0x0, 0x400),
    )
}

LOG = logging.getLogger(__name__)

class GD32E230G8(CoreSightTarget):

    VENDOR = "GigaDevice"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0x08000000,  length=0x10000, blocksize=0x400, is_boot_memory=True,
            algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x2000)
        )

    def __init__(self, session):
        super(GD32E230G8, self).__init__(session, self.MEMORY_MAP)
        #self._svd_location = SVDFile.from_builtin("STM32F103xx.svd")

    # def post_connect_hook(self):
    #     self.write_memory(DBGMCU_CR, DBGMCU_VAL)

    def is_locked(self):
        status = self.read32(FMC_OBSTAT)
        return (status & 0x2) != 0
    
    def _flash_unlock(self):
        # Unlock FMC_CTL
        self.write32(FMC_KEY, KEY1)
        self.write32(FMC_KEY, KEY2)

    def _option_unlock(self):
        self._flash_unlock()

        # Unlock OBWEN
        self.write32(FMC_OBKEY, KEY1)
        self.write32(FMC_OBKEY, KEY2)

    def _option_erase(self):
        self._option_unlock()

        self.write32(FMC_CTL, OBER | OBWEN)
        self.write32(FMC_CTL, OBER | OBWEN | START)

        with Timeout(FLASH_ERASE_TIMEOUT) as to:
            while to.check():
                status = self.read32(FMC_STAT)
                if (status & BUSY) == 0:
                    break
                sleep(0.1)
            else:
                # Timed out
                LOG.error("Option byte erase timeout")
                return False
            
        return True

    def mass_erase(self):
        if self.is_locked():

            ob_user = self.read16(0x1FFFF802)
        
            if not self._option_erase():
                LOG.error("%s: option byte unlock fail", self.part_number)
                raise exceptions.TargetError("unable to unlock device")
            
            self._option_unlock()
            self.write32(FMC_CTL, OBPG | OBWEN)

            self.write16(0x1FFFF800, 0x5AA5)
            self.write16(0x1FFFF802, ob_user)

            with Timeout(FLASH_ERASE_TIMEOUT) as to:
                while to.check():
                    status = self.read32(FMC_STAT)
                    if (status & BUSY) == 0:
                        break
                    sleep(0.1)
                else:
                    # Timed out
                    LOG.error("%s: mass erase failed", self.part_number)
                    raise exceptions.TargetError("unable to unlock device")
        else:
            eraser = FlashEraser(self.session, FlashEraser.Mode.CHIP)
            eraser._log_chip_erase = False
            eraser.erase()



