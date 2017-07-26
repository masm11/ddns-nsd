#!/usr/bin/env ruby

require 'socket'

module Base
  def dump(ary, beg, len)
    print "---------------------------------\n"
    print "[i=0x#{'%x' % beg}, len=#{len}]\n"
    len.times do |i|
      print ' %02x' % ary[beg + i]
      print "\n" if i % 16 == 15
    end
    print "\n" unless len % 16 == 0
  end
  
  def read_2(data, i)
    [ data[i] << 8 | data[i + 1], i + 2 ]
  end
  
  def read_4(data, i)
    [ data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3], i + 4]
  end
  
  def read_domainname(data, i)
    name = ''
    
    while data[i] != 0
      case data[i] & 0xc0
      when 0x00
        len = data[i]
        i += 1
        len.times do
          name += '%c' % data[i]
          i += 1
        end
        name += '.'
      when 0x40, 0x80
        raise 'Unknown compression.'
      when 0xc0
        j, i = read_2(data, i)
        j &= ~0xc000
        return [ name + read_domainname(data, j)[0], i ]
      end
    end
    
    [ name, i + 1 ]
  end
end

class Request
  include Base
  
  class Zone
    include Base
    
    def read(data, i)
      puts "Zone:------------------------------"
      zname, i = read_domainname(data, i)
      puts "ZNAME='#{zname}'"
      
      ztype, i = read_2(data, i)
      zclass, i = read_2(data, i)
      puts "ZTYPE=#{ztype}"   # must be SOA.
      puts "ZCLASS=#{zclass}" # zone's class.
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Prerequisite
    include Base
    
    def read(data, i)
      puts "Prereq:------------------------------"
      rrname, i = read_domainname(data, i)
      
      rrtype, i = read_2(data, i)
      rrclass, i = read_2(data, i)
      rrttl, i = read_4(data, i)
      rrrdlength, i = read_2(data, i)
      rrrdata = data[i ... i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Update
    include Base
    
    def read(data, i)
      puts "Update:------------------------------"
      rrname, i = read_domainname(data, i)
      
      rrtype, i = read_2(data, i)
      rrclass, i = read_2(data, i)
      rrttl, i = read_4(data, i)
      rrrdlength, i = read_2(data, i)
      rrrdata = data[i...i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Additional
    include Base
    
    def read(data, i)
      puts "Additional:------------------------------"
      rrname, i = read_domainname(data, i)
      
      rrtype, i = read_2(data, i)
      rrclass, i = read_2(data, i)
      rrttl, i = read_4(data, i)
      rrrdlength, i = read_2(data, i)
      rrrdata = data[i...i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  def initialize(data)
    i = 0
    
    @id, i = read_2(data, i)
    puts "ID=0x#{"%04x" % @id}"
    
    vals, i = read_2(data, i)
    @qr = (vals >> 15) & 1
    @opcode = (vals >> 11) & 0x0f
    @z = (vals >> 4) & 0x7f
    @rcode = (vals >> 0) & 0x0f
    
    zocount, i = read_2(data, i)
    prcount, i = read_2(data, i)
    upcount, i = read_2(data, i)
    adcount, i = read_2(data, i)
    puts "QR=#{@qr} (#{@qr == 0 ? 'req' : 'res'})"
    puts "Opcode=0x#{'%x' % @opcode} (#{@opcode == 5 ? 'UPDATE' : '??????'})"
    puts "Z=0x#{'%02x' % @z} (#{@z == 0 ? 'ok' : 'unknown'})"
    puts "RCODE=0x#{'%x' % @rcode}"
    puts "ZOCOUNT=#{zocount} (#zone)"
    puts "PRCOUNT=#{prcount} (#prereq)"
    puts "UPCOUNT=#{upcount} (#update)"
    puts "ADCOUNT=#{adcount} (#additional)"
    
    @zones = []
    i = 12
    zocount.times do
      zone = Zone.new
      i = zone.read(data, i)
      @zones << zone
    end
    
    @prerequisites = []
    prcount.times do
      pr = Prerequisite.new
      i = pr.read(data, i)
      @prerequisites << pr
    end
    
    @updates = []
    upcount.times do
      update = Update.new
      i = update.read(data, i)
      @updates << update
    end
    
    @additionals = []
    adcount.times do
      additional = Additional.new
      i = additional.read(data, i)
      @additionals << additional
    end
  end
end

def try_tcp
  sock = TCPServer.open('127.0.0.2', 53)
  
  puts "tcp: accepting..."
  s = sock.accept
  while true
    puts "tcp: recving..."
    data = s.recv(65536)
    break if data.length == 0
    puts "TCP:"
    puts data
  end
end

def try_udp
  sock = UDPSocket.new
  sock.bind('127.0.0.2', 53)
  
  while true
    puts "udp: recving..."
    data = sock.recv(65536).unpack('C*')   # ASCII-8BIT
    puts 'UDP:'
    
    req = Request.new(data)
  end
end

Thread.new do
  try_tcp
end
try_udp
