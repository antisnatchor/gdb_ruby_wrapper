

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

#================================= Gdb class ==================
class Gdb
  def initialize(pid, verbose)
   @gdb = IO.popen(["gdb", "attach", "#{pid}"], "r+")
   @signal = nil
   @verbose = verbose
   read_gdb_stdout
  end

  def read_gdb_stdout
    gdb_stdout = []
    begin
        ln = ''
        while result = IO.select([@gdb])
          next if result.empty?
          chars = @gdb.read(1)
          break if chars.nil?
          ln << chars
          break if ln == '(gdb) '
          if ln[-1] == ?\n
            gdb_stdout << ln
            parse_signal(ln)
            ln = ''
          end
        end
    rescue Exception => e
      puts e.backtrace if @verbose
    end
    puts gdb_stdout if @verbose
    gdb_stdout
  end

  def write_gdb_stdin(cmd)
    begin
      @gdb.puts(cmd.strip)
    rescue Exception => e
      puts e.backtrace if @verbose
    end
    read_gdb_stdout
  end

  def parse_signal(line)
     signal = nil
     if line[/^Program received signal/]
       @signal = line.split("Program received signal ").last.split(',').first
       puts "[+] [#{Time.now}]>  Debugged process received signal #{@signal}"
     end
     signal
  end

  def get_signal
    @signal
  end
end

#================================= Controller class ==================

class Controller

  def initialize(pname, sleep_time, verbose, notifier)
    @pname = pname
    @sleep_time = sleep_time
    @debugging_session = Hash.new
    @verbose = verbose
    @notifier = notifier
    get_process_pid
  end

  def get_process_pid
    @ppid = nil
    begin
    Dir['/proc/[0-9]*/cmdline'].each do|p|
      process = File.read(p)
      if process[/^\/usr\/bin\/#{Regexp.new("#{@pname}")}/]
        @ppid = p.split('/')[2]
        puts "[+] [#{Time.now}]> /usr/bin/#{@pname} ELF has PID #{@ppid}"
        break
      end
    end
    rescue Exception => e
      puts e.backtrace if @verbose
    end
    @ppid
  end

  def attach
    if @ppid != nil
      @gdbc = Gdb.new(@ppid, @verbose)
      puts "[+] [#{Time.now}]> Attached to #{@pname} process, PID #{@ppid}"
      @gdbc.write_gdb_stdin('continue')
    else
      # TODO -> TERMINATE
    end
  end

  def dump_registers
    @debugging_session['time'] = Time.now
    @debugging_session['signal'] = @gdbc.get_signal
    @debugging_session['registers'] = @gdbc.write_gdb_stdin('info registers')
  end

  def quit
    notify_fuzzer_for_signal
    @gdbc.write_gdb_stdin('quit')
    @gdbc.write_gdb_stdin('y')
  end

  def debug
    attach
    dump_registers
    quit
    puts "[+] [#{Time.now}]> Sleeping #{@sleep_time} seconds before re-attaching to new #{@pname} PID"
    sleep @sleep_time
    get_process_pid
    notify_fuzzer_for_reattach
    # recursively call itself after <sleep_time> seconds
    debug
  end

  def notify_fuzzer_for_signal
    @notifier.send_signal_info(@debugging_session)
    puts "[+] [#{Time.now}]> Notifying fuzzer for signal, data: \n" + @debugging_session.inspect
  end

  def notify_fuzzer_for_reattach
    @notifier.send_resume_request
    puts "[+] [#{Time.now}]> Notifying fuzzer for reattach"
  end
end


#================================= Notifier class ==================
require 'uri'
require 'net/http'
require 'json'

class Notifier

  def initialize(ip, port, is_https)
    if is_https
      @uri = URI("https://#{ip}:#{port}/notify")
      @http = Net::HTTP.new(@uri.host, @uri.port)
      @http.use_ssl = true
      # unless you're on an internal network you trust, remove the line below ;-)
      @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    else
      @uri = URI("http://#{ip}:#{port}/notify")
      @http = Net::HTTP.new(@uri.host, @uri.port)
    end

  end

  # sends a POST request with a JSON body like:
  # { 'time': 'XXX', 'signal': 'SIGXXX', 'registers': 'rax blabla, ...'}
  def send_signal_info(data)
    begin
      request = Net::HTTP::Post.new("#{@uri.request_uri}/signal")
      response = @http.request(request, data.to_json)
    rescue => e
      puts e
    end
  end

  # just in case you need it to let your fuzzer components continue
  def send_resume_request
    begin
      request = Net::HTTP::Get.new("#{@uri.request_uri}/reattach")
      response = @http.request(request)
    rescue => e
      puts e
    end
  end

end

#================================= Init ==================

puts "[+] GDB Ruby wrapper for x86/x86_64 Linux binaries - by antisnatchor"

# this is the executable name you want to attach GDB to it. Make sure it's in /usr/bin
process_name = "opsec"

sleep_before_reattach = 20 #seconds
verbose_gdb_output = false

# HTTP server that will handle the JSON notification with Crash data.
fuzzing_server_ip = "172.16.37.164"
fuzzing_server_port = 80
is_fuzzing_server_https = false

notifier = Notifier.new(
                fuzzing_server_ip, fuzzing_server_port, 
                is_fuzzing_server_https)

controller = Controller.new(
                process_name, sleep_before_reattach, 
                verbose_gdb_output, notifier)

controller.debug





