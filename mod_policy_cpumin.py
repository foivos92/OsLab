#!/usr/bin/env python
import os
import sys
totalCpu = 2000
avail = 2000
used = 0
needed = 0
fraction=0

commandList = sys.stdin.readlines();
commands = []
for command in commandList:
    command=command.replace("\n","")
    commands.append(command.split(':'))
results = []

for command in commands:
    needed += int(command[3])
    if(int(command[3]) <=  avail):
        avail-= int(command[3])
        result = [command[1],command[3]]
        results.append(result)

used = totalCpu - avail
if (needed>0):
  fraction =(1.0)* totalCpu/needed

score = (1.0)*(totalCpu-needed)
sys.stdout.write("score:%f" %float(score)+"\n")

for result in results:
    shares = int(result[1])*fraction
    sys.stdout.write("set_limit:" + result[0] + ":cpu.shares:" + str(int(float(shares)))+ "\n")




























