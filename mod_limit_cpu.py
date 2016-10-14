#!/usr/bin/env python
import os
import sys

start ="/sys/fs/cgroup/cpu/"
dirMonitor  = "/sys/fs/cgroup/cpu/monitor/"

def create(appName):
        os.makedirs (dirMonitor + appName ,777 )
	return

def remove(appName):
        os.rmdir(dirMonitor + appName)
	return

def add(app_name, id1):
        task = open(dirMonitor + app_name + "/tasks",'a+')
        task.write(id1)
        task.close()
	return

def set_limit(app_name, cpushare):
        shares = open(dirMonitor+app_name+ "/cpu.shares",'a+')
        shares.write(cpushare)
        shares.close()
	return

#------------------main---------------------
commandList = sys.stdin.readlines();
commands = []
for command in commandList:
    command=command.replace("\n","")
    commands.append(command.split(':'))
for command in commands:
    if(command[0] == 'create'):
        create(command[3])
    elif(command[0] == 'remove'):
        remove(command[3])
    elif(command[0] == 'add'):
        add(command[3],command[4])
    elif(command[0] == 'set_limit'):
        set_limit(command[3],command[5])
    else:
        print "Unknown Command\n"
