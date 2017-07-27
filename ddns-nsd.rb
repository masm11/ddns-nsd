#!/usr/bin/env ruby

require 'socket'

module Base
  
  OPCODE_UPDATE = 5
  
  TYPE_A     = 1
  TYPE_NS    = 2
  TYPE_MD    = 3
  TYPE_MF    = 4
  TYPE_CNAME = 5
  TYPE_SOA   = 6
  TYPE_MB    = 7
  TYPE_MG    = 8
  TYPE_MR    = 9
  TYPE_NULL  = 10
  TYPE_WKS   = 11
  TYPE_PTR   = 12
  TYPE_HINFO = 13
  TYPE_MINFO = 14
  TYPE_MX    = 15
  TYPE_TXT   = 16
  
  CLASS_IN   = 1
  CLASS_CS   = 2
  CLASS_CH   = 3
  CLASS_HS   = 4
  CLASS_NONE = 254
  
  RCODE_NOERROR  = 0
  RCODE_FORMERR  = 1
  RCODE_SERVFAIL = 2
  RCODE_NXDOMAIN = 3
  RCODE_NOTIMP   = 4
  RCODE_REFUSED  = 5
  RCODE_YXDOMAIN = 6
  RCODE_YXRRSET  = 7
  RCODE_NXRRSET  = 8
  RCODE_NOTAUTH  = 9
  RCODE_NOTZONE  = 10
  
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
    
    attr_reader :name
    attr_reader :type
    attr_reader :class
    
    def read(data, i)
      puts "Zone:------------------------------"
      @name, i = read_domainname(data, i)
      puts "ZNAME='#{@name}'"
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      puts "ZTYPE=#{@type}"   # must be SOA.
      puts "ZCLASS=#{@class}" # zone's class.
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Prerequisite
    include Base
    
    # CLASS    TYPE     RDATA    Meaning
    # ------------------------------------------------------------
    # ANY      ANY      empty    Name is in use
    # ANY      rrset    empty    RRset exists (value independent)
    # NONE     ANY      empty    Name is not in use
    # NONE     rrset    empty    RRset does not exist
    # zone     rrset    rr       RRset exists (value dependent)

    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def read(data, i)
      puts "Prereq:------------------------------"
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i ... i + rdlength]
      i += rdlength
      
      puts "RR name=#{@name}"
      puts "RR type=#{@type}"
      puts "RR class=#{@class}"
      puts "RR ttl=#{@ttl}"
      puts "RR rdlength=#{rdlength}"
      puts "RR rdata=#{@rdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Update
    include Base
    
    # CLASS    TYPE     RDATA    Meaning
    # ---------------------------------------------------------
    # ANY      ANY      empty    Delete all RRsets from a name
    # ANY      rrset    empty    Delete an RRset
    # NONE     rrset    rr       Delete an RR from an RRset
    # zone     rrset    rr       Add to an RRset
    
    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def read(data, i)
      puts "Update:------------------------------"
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      i += rdlength
      
      puts "RR name=#{@name}"
      puts "RR type=#{@type}"
      puts "RR class=#{@class}"
      puts "RR ttl=#{@ttl}"
      puts "RR rdlength=#{rdlength}"
      puts "RR rdata=#{@rdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Additional
    include Base
    
    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def read(data, i)
      puts "Additional:------------------------------"
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      i += rdlength
      
      puts "RR name=#{@name}"
      puts "RR type=#{@type}"
      puts "RR class=#{@class}"
      puts "RR ttl=#{@ttl}"
      puts "RR rdlength=#{rdlength}"
      puts "RR rdata=#{@rdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  attr_reader :id
  attr_reader :qr
  attr_reader :opcode
  attr_reader :z
  attr_reader :rcode
  attr_reader :zones
  attr_reader :prerequisites
  attr_reader :updates
  attr_reader :additionals
  
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
