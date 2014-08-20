gdb_ruby_wrapper
================

GDB Ruby wrapper for x86/x86_64 Linux binaries

# Author: antisnatchor

# ====================== GDB-Ruby wrapper =====================#
# I ended up writing this because @chrisrohlf hasn't ported yet
# RagWeed to x86_64 and I needed to monitor a 64bit Linux process while fuzzing it.
# I also didn't want to use GDB's Python API.
#
# Given a <process_name>, the wrapper will look into /proc/ searching for its PID,
# then will attach GDB to it. When the debugged process receives a signal,
# signal type and registers info are dumped and the process is stopped.
# The dumped info is then sent via HTTP(S) to a server of your choice.
# After <sleep_before_reattach> seconds the wrapper will call itself again recursively
# re-attaching GDB to the process new PID.
#
# NOTE: You need to monitor the target process and re-start it yourself,
# the wrapper doesn't do that for you so far. 
# Make sure you adjust <sleep_before_reattach> accordingly.
