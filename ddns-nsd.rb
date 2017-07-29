#!/usr/bin/env ruby

require 'socket'
require 'base64'
require 'openssl'

@data = [
  {
    name: 'pink.masm11.ddo.jp.',
    records: [],
  },
]

class Ex < StandardError
  attr_reader :code
  def initialize(code, msg)
    super(msg)
    @code = code
  end
end

module Base
  
  OPCODE_UPDATE = 5
  
  TYPE_A          = 1
  TYPE_NS         = 2
  TYPE_MD         = 3
  TYPE_MF         = 4
  TYPE_CNAME      = 5
  TYPE_SOA        = 6
  TYPE_MB         = 7
  TYPE_MG         = 8
  TYPE_MR         = 9
  TYPE_NULL       = 10
  TYPE_WKS        = 11
  TYPE_PTR        = 12
  TYPE_HINFO      = 13
  TYPE_MINFO      = 14
  TYPE_MX         = 15
  TYPE_TXT        = 16
  TYPE_RP         = 17
  TYPE_AFSDB      = 18
  TYPE_SIG        = 24
  TYPE_KEY        = 25
  TYPE_AAAA       = 28
  TYPE_LOC        = 29
  TYPE_SRV        = 33
  TYPE_NAPTR      = 35
  TYPE_KX         = 36
  TYPE_CERT       = 37
  TYPE_DNAME      = 39
  TYPE_OPT        = 41
  TYPE_APL        = 42
  TYPE_DS         = 43
  TYPE_SSHFP      = 44
  TYPE_IPSECKEY   = 45
  TYPE_RRSIG      = 46
  TYPE_NSEC       = 47
  TYPE_DNSKEY     = 48
  TYPE_DHCID      = 49
  TYPE_NSEC3      = 50
  TYPE_NSEC3PARAM = 51
  TYPE_TLSA       = 52
  TYPE_HIP        = 55
  TYPE_CDS        = 59
  TYPE_CDNSKEY    = 60
  TYPE_TKEY       = 249
  TYPE_TSIG       = 250
  TYPE_IXFR       = 251
  TYPE_AXFR       = 252
  TYPE_NONE       = 254
  TYPE_ANY        = 255
  TYPE_CAA        = 257
  TYPE_DLV        = 32769
  TYPE_TA         = 32768
  
  CLASS_IN   = 1
  CLASS_CS   = 2
  CLASS_CH   = 3
  CLASS_HS   = 4
  CLASS_NONE = 254
  CLASS_ANY  = 255
  
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
  
  TSIG_ERROR_BADSIG   = 16
  TSIG_ERROR_BADKEY   = 17
  TSIG_ERROR_BADTIME  = 18
  
  def dump(ary, beg, len)
    # return
    print "---------------------------------\n"
    print "[i=0x#{'%x' % beg}, len=#{len}]\n"
    len.times do |i|
      print ' %02x' % ary[beg + i]
      if i % 16 == 15
        print "\n"
      end
    end
    print "\n" unless len % 16 == 0
  end
  
  def read_2(data, i)
    [ data[i] << 8 | data[i + 1], i + 2 ]
  end
  
  def read_4(data, i)
    [ data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3], i + 4]
  end
  
  def read_6(data, i)
    [ data[i] << 40 | data[i + 1] << 32 | data[i + 2] << 24 | data[i + 3] << 16 | data[i + 4] << 8 | data[i + 5], i + 6]
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
    
    attr_reader :start_pos
    attr_reader :name
    attr_reader :type
    attr_reader :class
    
    def self.create(data, i)
      zone = Zone.new
      i = zone.read(data, i)
      [ zone, i ]
    end
    
    def read(data, i)
      puts "Zone:"
      @start_pos = i
      @name, i = read_domainname(data, i)
      puts "  name=#{@name}"
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      puts "  type=#{@type}"
      puts "  class=#{@class}"
      
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

    attr_reader :start_pos
    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def self.create(data, i)
      prereq = Prerequisite.new
      i = prereq.read(data, i)
      [ prereq, i ]
    end
    
    def read(data, i)
      puts "Prerequisite:"
      @start_pos = i
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i ... i + rdlength]
      i += rdlength
      
      puts "  name=#{@name}"
      puts "  type=#{@type}"
      puts "  class=#{@class}"
      puts "  ttl=#{@ttl}"
      puts "  rdlength=#{rdlength}"
      puts "  rdata=#{@rdata}"
      
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
    
    attr_reader :start_pos
    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def self.create(data, i)
      update = Update.new
      i = update.read(data, i)
      [ update, i ]
    end
    
    def read(data, i)
      puts "Update:"
      @start_pos = i
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      i += rdlength
      
      puts "  name=#{@name}"
      puts "  type=#{@type}"
      puts "  class=#{@class}"
      puts "  ttl=#{@ttl}"
      puts "  rdlength=#{rdlength}"
      puts "  rdata=#{@rdata}"
      
      dump(data, i, data.length - i)
      i
    end
  end
  
  class Additional
    include Base
    
    attr_reader :start_pos
    attr_reader :name
    attr_reader :type
    attr_reader :class
    attr_reader :ttl
    attr_reader :rdata
    
    def self.create(data, i)
      additional = Additional.new
      i = additional.read(data, i)
      [ additional, i ]
    end
    
    def read(data, i)
      puts "Additional:"
      @start_pos = i
      @name, i = read_domainname(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      i += rdlength
      
      puts "  name=#{@name}"
      puts "  type=#{@type}"
      puts "  class=#{@class}"
      puts "  ttl=#{@ttl}"
      puts "  rdlength=#{rdlength}"
      puts "  rdata=#{@rdata}"
      
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
    puts "  QR=#{@qr} (#{@qr == 0 ? 'req' : 'res'})"
    puts "  Opcode=0x#{'%x' % @opcode} (#{@opcode == 5 ? 'UPDATE' : '??????'})"
    puts "  Z=0x#{'%02x' % @z} (#{@z == 0 ? 'ok' : 'unknown'})"
    puts "  RCODE=0x#{'%x' % @rcode}"
    puts "  ZOCOUNT=#{zocount} (#zone)"
    puts "  PRCOUNT=#{prcount} (#prereq)"
    puts "  UPCOUNT=#{upcount} (#update)"
    puts "  ADCOUNT=#{adcount} (#additional)"
    
    @zones = []
    zocount.times do
      zone, i = Zone.create(data, i)
      @zones << zone
    end
    
    @prerequisites = []
    prcount.times do
      pr, i = Prerequisite.create(data, i)
      @prerequisites << pr
    end
    
    @updates = []
    upcount.times do
      update, i = Update.create(data, i)
      @updates << update
    end
    
    @additionals = []
    adcount.times do
      additional, i = Additional.create(data, i)
      @additionals << additional
    end
  end
end
  
class TSIG
  include Base
  
  attr_reader :alg
  attr_reader :time
  attr_reader :fudge
  attr_reader :mac
  attr_reader :orig_id
  attr_reader :error
  attr_reader :other
  
  def initialize(rdata)
    i = 0
    @alg, i = read_domainname(rdata, i)
    @time, i = read_6(rdata, i)
    @fudge, i = read_2(rdata, i)
    mac_size, i = read_2(rdata, i)
    @mac = rdata[i ... i + mac_size]
    i += mac_size
    @orig_id, i = read_2(rdata, i)
    @error, i = read_2(rdata, i)
    other_len, i = read_2(rdata, i)
    @other = rdata[i ... i + other_len]
    puts "TSIG:"
    puts "  alg: #{@alg}"
    puts "  time: #{@time}"
    puts "  fudge: #{@fudge}"
    puts "  mac: #{@mac}"
    puts "  orig_id: #{@orig_id}"
    puts "  error: #{@error}"
    puts "  other: #{@other}"
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
    data, sa = sock.recvfrom(65536)
    data = data.unpack('C*')   # ASCII-8BIT
    puts 'UDP:'
    
    begin
      req = Request.new(data)
      
      # check TSIG.
      
      if req.additionals.length >= 1
        if req.additionals.last.type == Request::TYPE_TSIG
          puts "last additional rr is tsig."
          
          unless req.additionals.select{ |rr| rr.type == Request::TYPE_TSIG }.length == 1
            # TSIG RR が複数あるらしい
            raise Ex.new(Request::RCODE_FORMERR, 'multiple TSIG.')
          end
          
          tsig = TSIG.new(req.additionals.last.rdata)
          now = Time.now.to_i
          unless now >= tsig.time && now < tsig.time + tsig.fudge
            raise Ex.new(Request::RCODE_NOTAUTH, 'tsig badtime.')
          end
          
          raw = data[0 ... req.additionals.last.start_pos]
          if raw[11] != 0
            raw[11] -= 1
          else
            raw[10] -= 1
            raw[11] = 255
          end
          raw = raw.pack('C*')
          key = Base64.decode64('pRP5FapFoJ95JEL06sv4PQ==')
          hmac = OpenSSL::HMAC.new(key, 'md5')
          puts '--------'
          p raw
          hmac.update(raw)
          p req.additionals.last.name.split('.').map{ |p|
            [p.length].pack('C') + p
          }.join('') + "\0"
          hmac.update(req.additionals.last.name.split('.').map{ |p|
                        [p.length].pack('C') + p
                      }.join('') + "\0")
          p [req.additionals.last.class].pack('n')
          hmac.update([req.additionals.last.class].pack('n'))
          p [0].pack('n')
          hmac.update([0].pack('n'))
          p tsig.alg.split('.').map{ |p|
            [p.length].pack('C') + p
          }.join('') + "\0"
          hmac.update(tsig.alg.split('.').map{ |p|
                        [p.length].pack('C') + p
                      }.join('') + "\0")
          p [tsig.time >> 32].pack('n')
          hmac.update([tsig.time >> 32].pack('n'))
          p [tsig.time].pack('N')
          hmac.update([tsig.time].pack('N'))
          p [tsig.fudge].pack('n')
          hmac.update([tsig.fudge].pack('n'))
          p [tsig.error].pack('n')
          hmac.update([tsig.error].pack('n'))
          p [tsig.other.length].pack('n')
          hmac.update([tsig.other.length].pack('n'))
          p tsig.other.pack('C*')
          hmac.update(tsig.other.pack('C*'))
          puts '--------'
          puts "#{hmac.digest.unpack('C*')}"
          puts "#{tsig.mac}"
        end
      end
      
      # check zone.
      
      if req.zones.length != 1
        raise Ex.new(Request::RCODE_FORMERR, 'zone count is not 1.')
      end
      if req.zones[0].type != Request::TYPE_SOA
        raise Ex.new(Request::RCODE_FORMERR, 'zone is not SOA.')
      end
      data_alter = @data.dup
      data = data_alter.select{ |dat| req.zones[0].name == dat[:name] }.first
      unless data
        raise Ex.new(Request::RCODE_NOTAUTH, 'unknown zone name.')
      end
      
      # check prerequisites.
      
      req.prerequisites.each do |prereq|
        if prereq.class == Request::CLASS_ANY
          unless prereq.ttl == 0 && prereq.rdata.length == 0
            raise Ex.new(Request::RCODE_FORMERR, 'prereq 1.')
          end
          if prereq.type == Request::TYPE_ANY
            if data[:records].select{ |rr| rr[:name] == prereq.name }.length == 0
              raise Ex.new(Request::RCODE_NXDOMAIN, 'prereq: 2.')
            end
          else
            if data[:records].select{ |rr|
                 rr[:name] == prereq.name && rr[:type] == prereq.type
               }.length == 0
              raise Ex.new(Request::RCODE_NXRRSET, 'prereq: 3.')
            end
          end
        end
      end
      
      req.prerequisites.each do |prereq|
        if prereq.class == Request::CLASS_NONE
          unless prereq.ttl == 0 && prereq.rdata.length == 0
            raise Ex.new(Request::RCODE_FORMERR, 'prereq 4.')
          end
          
          if prereq.type == Request::TYPE_ANY
            unless data[:records].select{ |rr| rr[:name] == prereq.name }.length == 0
              raise Ex.new(Request::RCODE_YXDOMAIN, 'prereq: 5.')
            end
          else
            unless data[:records].select{ |rr|
                     rr[:name] == prereq.name && rr[:type] == prereq.type
                   }.length == 0
              raise Ex.new(Request::RCODE_YXRRSET, 'prereq: 6.')
            end
          end
        end
      end
      
      req.prerequisites.each do |prereq|
        if prereq.class == req.zones[0].class
          unless prereq.ttl == 0
            raise Ex.new(Request::RCODE_FORMERR, 'prereq: 7.')
          end
          if data[:records].select{ |d|
               d[:name] == prereq.name && d[:type] == prereq.type && d[:rdata] == prereq.rdata
             }.length == 0
            raise Ex.new(Request::RCODE_NXRRSET, 'prereq: 8.')
          end
        end
      end
      
      # update
      
      req.updates.each do |update|
        unless [ req.zones[0].class, Request::TYPE_ANY, Request::TYPE_NONE ].include?(update.class)
          raise Ex.new(Request::RCODE_FORMERR, 'update: 1.')
        end
        unless update.name.end_with?(req.zones[0].name)
          raise Ex.new(Request::RCODE_NOTZONE, 'update: 2.')
        end
      end
      
      req.updates.each do |update|
        if update.class != Request::CLASS_ANY
          case update.type
          when Request::TYPE_A
          when Request::TYPE_AAAA
          when Request::TYPE_PTR
          when Request::TYPE_DHCID
          else
            puts "type=#{update.type}"
            raise Ex.new(Request::RCODE_FORMERR, 'update: 3.')
          end
        end
        if update.class == Request::CLASS_ANY || update.class == Request::CLASS_NONE
          unless update.ttl == 0
            raise Ex.new(Request::RCODE_FORMERR, 'update: 4.')
          end
        end
        if update.class == Request::CLASS_ANY
          unless update.rdata.length == 0
            raise Ex.new(Request::RCODE_FORMERR, 'update: 5.')
          end
          case update.type
          when Request::TYPE_A
          when Request::TYPE_AAAA
          when Request::TYPE_PTR
          when Request::TYPE_DHCID
          else
            raise Ex.new(Request::RCODE_FORMERR, 'update: 6.')
          end
        end
      end
      
      req.updates.each do |update|
        if update.class == req.zones[0].class
          replaced = false
          data[:records].each do |rr|
            if rr[:name] == update.name && rr[:type] == update.type
              rr[:ttl] = update.ttl
              rr[:rdata] = update.rdata
              replaced = true
            end
          end
          unless replaced
            rr = {
              name: update.name,
              type: update.type,
              ttl: update.ttl,
              rdata: update.rdata,
            }
            data[:records] << rr
          end
        end
        if update.class == Request::CLASS_ANY && update.type == Request::TYPE_ANY
          # fixme: 3.4.2.3.
          puts "del1."
        end
        if update.class == Request::CLASS_NONE
          # fixme: 3.4.2.4.
          puts "del2."
        end
      end
      
      # response
      
      @data = data_alter
      puts @data
      
      res = [
        (req.id >> 8) & 0xff, req.id & 0xff,
        0x80 | Request::OPCODE_UPDATE << 3, 0,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
      ]
      res = res.pack('C*')
      # sa=[ AF_INET/INET6, port, hostname, host_ipaddr ]
      sa = Addrinfo.getaddrinfo(sa[3], sa[1], sa[0], :DGRAM)[0]
      sock.send(res, 0, sa)
      
      puts "OK."
      
    rescue => e
      puts e.to_s
      puts e.backtrace
    end
    
  end
end

Thread.new do
  try_tcp
end
try_udp
