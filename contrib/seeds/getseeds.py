#!/usr/bin/env python3
# Copyright (c) 2019 The RomanceBitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import requests
data = requests.get('http://sman.pw/nodes/peers.json').json()
for node in data:
	print(node + ':6502')
