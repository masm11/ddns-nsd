#!/usr/bin/env ruby

#    ddns-nsd - DNS Dynamic Updater for NSD.
#    Copyright (C) 2017 Yuuki Harano
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'syslog'
require 'socket'
require 'resolv-replace'
require 'base64'
require 'openssl'
require 'json'
require 'yaml'

Syslog.open 'ddns-nsd'

module Log
  def debug(msg)
    Syslog.debug '%s', msg
  end
  def info(msg)
    Syslog.info '%s', msg
  end
  def err(msg)
    Syslog.err '%s', msg
  end
  module_function :debug
  module_function :info
  module_function :err
end

class RCode < StandardError
  attr_reader :code
  attr_reader :level
  def initialize(level, code, msg)
    super(msg)
    @level = level
    @code = code
  end
end

class FormErr < RCode
  def initialize(msg)
    super(:err, Request::RCODE_FORMERR, msg)
  end
end
class ServFail < RCode
  def initialize(msg)
    super(:err, Request::RCODE_SERVFAIL, msg)
  end
end
class NxDomain < RCode
  def initialize(msg)
    super(:info, Request::RCODE_NXDOMAIN, msg)
  end
end
class NotImp < RCode
  def initialize(msg)
    super(:err, Request::RCODE_NOTIMP, msg)
  end
end
class Refused < RCode
  def initialize(msg)
    super(:err, Request::RCODE_REFUSED, msg)
  end
end
class YxDomain < RCode
  def initialize(msg)
    super(:info, Request::RCODE_YXDOMAIN, msg)
  end
end
class YxRRSet < RCode
  def initialize(msg)
    super(:info, Request::RCODE_YXRRSET, msg)
  end
end
class NxRRSet < RCode
  def initialize(msg)
    super(:info, Request::RCODE_NXRRSET, msg)
  end
end
class NotAuth < RCode
  def initialize(msg)
    super(:err, Request::RCODE_NOTAUTH, msg)
  end
end
class NotZone < RCode
  def initialize(msg)
    super(:err, Request::RCODE_NOTZONE, msg)
  end
end

class String
  def to_wire_format
    downcase.split('.').map{ |p| [p.length].pack('C') + p }.join('') + "\0"
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
    return
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
  
  def alter_dhcid_rdata!(rdata)
    if rdata.length >= 2
      if rdata[0] == 0x00 && rdata[1] == 0x02
        rdata[1] = 0x01
      end
    end
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
  
  def read_wire_format(data, i)
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
        return [ name + read_wire_format(data, j)[0], i ]
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
      Log.debug "Zone:"
      @start_pos = i
      @name, i = read_wire_format(data, i)
      Log.debug "  name=#{@name}"
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      Log.debug "  type=#{@type}"
      Log.debug "  class=#{@class}"
      
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
      Log.debug "Prerequisite:"
      @start_pos = i
      @name, i = read_wire_format(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i ... i + rdlength]
      alter_dhcid_rdata!(@rdata) if @type == Request::TYPE_DHCID
      i += rdlength
      
      Log.debug "  name=#{@name}"
      Log.debug "  type=#{@type}"
      Log.debug "  class=#{@class}"
      Log.debug "  ttl=#{@ttl}"
      Log.debug "  rdlength=#{rdlength}"
      Log.debug "  rdata=#{@rdata}"
      
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
      Log.debug "Update:"
      @start_pos = i
      @name, i = read_wire_format(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      alter_dhcid_rdata!(@rdata) if @type == Request::TYPE_DHCID
      i += rdlength
      
      Log.debug "  name=#{@name}"
      Log.debug "  type=#{@type}"
      Log.debug "  class=#{@class}"
      Log.debug "  ttl=#{@ttl}"
      Log.debug "  rdlength=#{rdlength}"
      Log.debug "  rdata=#{@rdata}"
      
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
      Log.debug "Additional:"
      @start_pos = i
      @name, i = read_wire_format(data, i)
      
      @type, i = read_2(data, i)
      @class, i = read_2(data, i)
      @ttl, i = read_4(data, i)
      rdlength, i = read_2(data, i)
      @rdata = data[i...i + rdlength]
      alter_dhcid_rdata!(@rdata) if @type == Request::TYPE_DHCID
      i += rdlength
      
      Log.debug "  name=#{@name}"
      Log.debug "  type=#{@type}"
      Log.debug "  class=#{@class}"
      Log.debug "  ttl=#{@ttl}"
      Log.debug "  rdlength=#{rdlength}"
      Log.debug "  rdata=#{@rdata}"
      
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
    Log.debug "ID=0x#{"%04x" % @id}"
    
    vals, i = read_2(data, i)
    @qr = (vals >> 15) & 1
    @opcode = (vals >> 11) & 0x0f
    @z = (vals >> 4) & 0x7f
    @rcode = (vals >> 0) & 0x0f
    
    zocount, i = read_2(data, i)
    prcount, i = read_2(data, i)
    upcount, i = read_2(data, i)
    adcount, i = read_2(data, i)
    Log.debug "  QR=#{@qr} (#{@qr == 0 ? 'req' : 'res'})"
    Log.debug "  Opcode=0x#{'%x' % @opcode} (#{@opcode == 5 ? 'UPDATE' : '??????'})"
    Log.debug "  Z=0x#{'%02x' % @z} (#{@z == 0 ? 'ok' : 'unknown'})"
    Log.debug "  RCODE=0x#{'%x' % @rcode}"
    Log.debug "  ZOCOUNT=#{zocount} (#zone)"
    Log.debug "  PRCOUNT=#{prcount} (#prereq)"
    Log.debug "  UPCOUNT=#{upcount} (#update)"
    Log.debug "  ADCOUNT=#{adcount} (#additional)"
    
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
    @alg, i = read_wire_format(rdata, i)
    @time, i = read_6(rdata, i)
    @fudge, i = read_2(rdata, i)
    mac_size, i = read_2(rdata, i)
    @mac = rdata[i ... i + mac_size]
    i += mac_size
    @orig_id, i = read_2(rdata, i)
    @error, i = read_2(rdata, i)
    other_len, i = read_2(rdata, i)
    @other = rdata[i ... i + other_len]
    Log.debug "TSIG:"
    Log.debug "  alg: #{@alg}"
    Log.debug "  time: #{@time}"
    Log.debug "  fudge: #{@fudge}"
    Log.debug "  mac: #{@mac}"
    Log.debug "  orig_id: #{@orig_id}"
    Log.debug "  error: #{@error}"
    Log.debug "  other: #{@other}"
  end
  
  attr_accessor :my_alg
  attr_accessor :my_key
  attr_accessor :my_keyname
end

def select_key(name)
  @keys.each do |key|
    Log.debug "'#{key['name']}' vs '#{name}'"
    if key['name'] == name
      raise "No secret in key #{name}" unless key['secret']
      raise "No alg in key #{name}" unless key['alg']
      sec = Base64.decode64(key['secret'])
      alg = key['alg'].sub(/\..*/, '').sub(/^hmac-/i, '')
      return [ sec, alg ]
    end
  end
  
  raise NotAuth.new("Unknown key: #{name}")
end

def check_tsig(req, data)
  unless req.additionals.length >= 1
    Log.err 'No TSIG.'
  end
  unless req.additionals.last.type == Request::TYPE_TSIG
    Log.err "Last additional RR is not TSIG."
  end
  
  unless req.additionals.count{ |rr| rr.type == Request::TYPE_TSIG } == 1
    # TSIG RR が複数あるらしい
    Log.err 'Multiple TSIG.'
    raise FormErr.new('Multiple TSIG RR.')
  end
  
  tsig = TSIG.new(req.additionals.last.rdata)
  now = Time.now.to_i
  unless now >= tsig.time && now < tsig.time + tsig.fudge
    Log.err 'TSIG bad time.'
    raise NotAuth.new('TSIG RR badtime.')
  end
  
  raw = data[0 ... req.additionals.last.start_pos]
  if raw[11] != 0
    raw[11] -= 1
  else
    raw[10] -= 1
    raw[11] = 255
  end
  raw = raw.pack('C*')
  key, alg = select_key(req.additionals.last.name)
  tsig.my_keyname = req.additionals.last.name
  tsig.my_key = key
  tsig.my_alg = alg
  hmac = OpenSSL::HMAC.new(key, alg)
  hmac.update(raw)
  hmac.update(req.additionals.last.name.to_wire_format)
  hmac.update([req.additionals.last.class].pack('n'))
  hmac.update([0].pack('N'))
  hmac.update(tsig.alg.to_wire_format)
  hmac.update([tsig.time >> 32].pack('n'))
  hmac.update([tsig.time].pack('N'))
  hmac.update([tsig.fudge].pack('n'))
  hmac.update([tsig.error].pack('n'))
  hmac.update([tsig.other.length].pack('n'))
  hmac.update(tsig.other.pack('C*'))
  
  Log.debug "#{hmac.digest.unpack('C*')}"
  Log.debug "#{tsig.mac}"
  unless hmac.digest == tsig.mac.pack('C*')
    Log.err 'TSIG signature not match.'
    raise NotAuth.new('Bad TSIG signagure.')
  end
  
  tsig
end

def sign_tsig(res, req, tsig)
  # 署名を計算する
  now = Time.now.to_i
  hmac = OpenSSL::HMAC.new(tsig.my_key, tsig.my_alg)
  hmac.update([tsig.mac.length].pack('n'))
  hmac.update(tsig.mac.pack('C*'))
  hmac.update(res.pack('C*'))
  hmac.update(tsig.my_keyname.to_wire_format)
  hmac.update([Request::CLASS_ANY].pack('n'))
  hmac.update([0].pack('N'))    # TTL
  hmac.update('hmac-md5.sig-alg.reg.int'.to_wire_format)
  hmac.update([now >> 32].pack('n'))
  hmac.update([now].pack('N'))
  hmac.update([300].pack('n'))  # fudge
  hmac.update([0].pack('n'))    # error
  hmac.update([0].pack('n'))    # other len
  digest = hmac.digest
  
  # TSIG RR の rdata を作る
  rdata = [
    "hmac-md5.sig-alg.reg.int".to_wire_format,
    [now >> 32].pack('n'),
    [now].pack('N'),
    [300].pack('n'),  # fudge
    [digest.length].pack('n'),
    digest,
    [req.id].pack('n'),
    [0].pack('n'),    # error
    [0].pack('n'),    # other len
  ].join('')
  
  if res[11] == 0xff
    res[10] += 1
    res[11] = 0
  else
    res[11] += 1
  end
  
  # TSIG RR を付ける。
  [
    res.pack('C*'),                  # 署名すべき返答パケット
    tsig.my_keyname.to_wire_format,  # name (key name)
    [Request::TYPE_TSIG].pack('n'),  # type
    [Request::CLASS_ANY].pack('n'),  # class
    [0].pack('N'),                   # TTL
    [rdata.length].pack('n'),        # rdlength
    rdata,                           # rdata
  ].join('')
end

def update_zone_file(data)
  Log.debug('update_zone_file')
  lines2 = File.readlines(data[:file]).map{ |s| s.sub(/\n\z/, '') }
  lines1 = []
  while lines2.length >= 1
    line = lines2.shift
    break if line =~ /^; DDNS-NSD:/
    lines1 << line
  end
  
  new_lines2 = []
  
  data[:records].sort{ |a, b|
    r = 0
    if r == 0
      r = a[:name] <=> b[:name]
    end
    if r == 0
      r = a[:type] <=> b[:type]
    end
    r
  }.each do |d|
    line = "#{d[:name]} #{d[:ttl]} IN "
    case d[:type]
    when Request::TYPE_A
      line += 'A '
      line += d[:rdata].join('.')
    when Request::TYPE_AAAA
      line += 'AAAA '
      line += (0...8).map{ |i|
        '%02x%02x' % [ d[:rdata][i * 2], d[:rdata][i * 2 + 1] ]
      }.join(':')
    when Request::TYPE_PTR
      line += 'PTR '
      i = 0
      while d[:rdata][i] != 0
        line += d[:rdata][i + 1 ... i + 1 + d[:rdata][i]].pack('C*')
        line += '.'
        i += 1 + d[:rdata][i]
      end
    when Request::TYPE_DHCID
      line += 'DHCID ( '
      line += Base64.encode64(d[:rdata].pack('C*')).strip.gsub(/\s/, '')
      line += ' )'
    end
    
    new_lines2 << "; #{Time.at(d[:timestamp]).to_s}".force_encoding('US-ASCII')
    new_lines2 << line.force_encoding('US-ASCII')
  end
  
  eq = true              # ファイル内容が完全に同じかどうか
  need_reload = false    # コメント以外に違う箇所があるかどうか。serial が増え、nsd が reload される。
  if lines2.length != new_lines2.length
    # Log.debug("line count changed. #{lines2.length}->#{new_lines2.length}")
    eq = false
    need_reload = true
  else
    # Log.debug("line count is not changed.")
    lines2.length.times do |i|
      # Log.debug("line#{'%02d' % i}: cls - #{lines2[i].class}")
      # Log.debug("line#{'%02d' % i}: cls + #{new_lines2[i].class}")
      # Log.debug("line#{'%02d' % i}: enc - #{lines2[i].encoding}")
      # Log.debug("line#{'%02d' % i}: enc + #{new_lines2[i].encoding}")
      # Log.debug("line#{'%02d' % i}: - #{lines2[i]}")
      # Log.debug("line#{'%02d' % i}: + #{new_lines2[i]}")
      # Log.debug("line#{'%02d' % i}: code - #{lines2[i].unpack('C*')}")
      # Log.debug("line#{'%02d' % i}: code + #{new_lines2[i].unpack('C*')}")
      if lines2[i] != new_lines2[i]
        if lines2[i] =~ /\A;/ && new_lines2[i] =~ /\A;/
          # Log.debug('both are comments. ignored.')
          # コメントが書き換わっただけで serial を増やすのは無駄。
          # でもファイルとしては書き換わってる。
          eq = false
          next
        end
        # Log.debug('differ.')
        eq = false
        need_reload = true
      end
    end
  end
  if eq
    Log.info("zone file #{data[:file]} not changed.")
  else
    Log.info("zone file #{data[:file]} differ.")
    now = Time.now.localtime
    new_file = "#{data[:file]}.new"
    history_file = "#{data[:file]}.new.#{now.strftime('%Y%m%d.%H%M%S')}.#{'%06d' % now.usec}"
    history_file = "#{@history}/#{history_file.gsub(/\//, ':')}"
    File.open(history_file, 'w', 0666) do |f|
      lines1.each do |l|
        if need_reload && l =~ /(\d+).+DDNS-NSD-SERIAL/
          date = Time.now.localtime.strftime('%Y%m%d')
          cur_serial = $1
          if cur_serial =~ /^#{date}(\d+)/
            rev = $1.to_i
            if rev >= 99
              rev = '00'
            else
              rev = '%02d' % (rev + 1)
            end
          else
            rev = '00'
          end
          new_serial = date + rev
          
          l = l.sub(/\d+/, new_serial)
        end
        f.puts l
      end
      f.puts "; DDNS-NSD: --- DON'T EDIT THIS LINE AND BELOW MANUALLY. ---"
      new_lines2.each do |l|
        f.puts l
      end
    end
    File.link(history_file, new_file)
    File.rename(new_file, "#{data[:file]}")
    Log.debug('update done.')
  end
  need_reload
end

def update_zone_files
  Log.debug('update_zone_files')
  
  @data.each do |data|
    if update_zone_file(data)
      @need_reload = true
    end
  end
end

def save_data
  json = JSON.pretty_generate(@data)
  File.open(@json_filename, 'w', 0666) do |f|
    f.write(json)
  end
end

def load_data(config)
  conf = YAML.load_file(config)
  
  @json_filename = conf['json']
  raise 'No json in config.' unless @json_filename
  @listen = conf['listen']
  # raise 'No listen in config.' unless @listen
  # raise 'listen must be an array of a string.' unless @listen.is_a?(Array)
  @keys = conf['keys']
  raise 'No keys in config.' unless @keys
  raise 'keys must be an array.' unless @keys.is_a?(Array)
  @restart_nsd = conf['restart_nsd']
  raise 'No restart_nsd in config.' unless @restart_nsd
  @history = conf['history']
  raise 'No history in config.' unless @history
  Dir.mkdir(@history) unless Dir.exist?(@history)
  
  zones = conf['zones']
  raise 'No zones in config.' unless zones
  raise 'zones must be an array.' unless zones.is_a?(Array)
  
  begin
    json = File.read(@json_filename)
    @data = JSON.parse(json, symbolize_names: true)
  rescue Errno::ENOENT => e
    Log.info "No JSON file."
    @data = []
  end
  
  zones.each do |zone|
    Log.debug(zone)
    raise 'A zone does not have name.' unless zone['name']
    raise 'A zone does not have file.' unless zone['file']
    data = @data.select{|d| d[:name] == zone['name']}.first
    unless data
      Log.info("New zone: #{zone['name']}")
      data = {}
      data[:name] = zone['name']
      data[:file] = zone['file']
      data[:records] = []
      @data << data
    else
      if data[:file] != zone['file']
        Log.info("Zone filename changed: #{zone['name']}")
        data[:file] = zone['file']
      end
    end
    raise "Zone file does not exist: #{data[:file]}" unless File.exists?(data[:file])
  end
  
  @data.each do |data|
    data[:records].each do |rr|
      rr[:timestamp] ||= Time.now.to_i
    end
  end
  
  save_data
end

def process_packet(data)
  
  data = data.unpack('C*')   # ASCII-8BIT
  
  tsig = nil
  
  begin
    now = Time.now.to_i
    
    req = Request.new(data)
    
    # check TSIG.
    tsig = check_tsig(req, data)
    
    # check zone.
    
    if req.zones.length != 1
      raise FormErr.new('Zone count is not 1.')
    end
    if req.zones[0].type != Request::TYPE_SOA
      raise FormErr.new("Zone's type isn't SOA.")
    end
    data_alter = @data.dup
    Log.info "zone: #{req.zones[0].name}"
    data = data_alter.select{ |dat| req.zones[0].name == dat[:name] }.first
    unless data
      raise NotAuth.new("Zone's name is unknown: '#{dat[:name]}'")
    end
    
    # check prerequisites.
    
    req.prerequisites.each do |prereq|
      if prereq.class == Request::CLASS_ANY
        unless prereq.ttl == 0
          raise FormErr.new("Bad prereq: TTL != 0.")
        end
        unless prereq.rdata.length == 0
          raise FormErr.new("Bad prereq: rdata not empty.")
        end
        
        if prereq.type == Request::TYPE_ANY
          unless data[:records].any?{ |rr| rr[:name] == prereq.name }
            raise NxDomain.new("Prereq not satisfied: No such named RR exists: '#{prereq.name}'")
          end
        else
          unless data[:records].any?{ |rr| rr[:name] == prereq.name && rr[:type] == prereq.type }
            raise NxRRSet.new("Prereq not satisfied: No such named and typed RR exists: '#{prereq.name}', #{prereq.type}")
          end
        end
      end
    end
    
    req.prerequisites.each do |prereq|
      if prereq.class == Request::CLASS_NONE
        unless prereq.ttl == 0
          raise FormErr.new("Bad prereq: TTL != 0..")
        end
        unless prereq.rdata.length == 0
          raise FormErr.new("Bad prereq: rdata not empty.")
        end
        
        if prereq.type == Request::TYPE_ANY
          if data[:records].any?{ |rr| rr[:name] == prereq.name }
            raise YxDomain.new("Prereq not satisfied: Such a named RR exists: '#{prereq.name}'")
          end
        else
          if data[:records].any?{ |rr| rr[:name] == prereq.name && rr[:type] == prereq.type }
            raise YxRRSet.new("Prereq not satisfied: Such a named and typed RR exists: '#{prereq.name}', #{prereq.type}")
          end
        end
      end
    end
    
    req.prerequisites.each do |prereq|
      if prereq.class == req.zones[0].class
        unless prereq.ttl == 0
          raise FormErr.new("Bad prereq: TTL != 0.")
        end
        
        prereq_rrset = req.prerequisites.select{ |p|
          p.class == req.zones[0].class &&
            p.name == prereq.name &&
            p.type == prereq.type
        }.sort{ |a, b|
          a.rdata <=> b.rdata
        }
        zone_rrset = data[:records].select{ |d|
          d[:name] == prereq.name && d[:type] == prereq.type
        }.sort{ |a, b|
          a.rdata <=> b.rdata
        }
        unless prereq_rrset.length == zone_rrset.length
          raise NxRRSet.new("Prereq not satisfied: RRset not match.")
        end
        prereq_rrset.length.times do |i|
          p = prereq_rrset[i]
          d = zone_rrset[i]
          # ttl は比較しない。
          unless p.rdata == d[:rdata]
            raise NxRRSet.new("Prereq not satisfied: RRset not match.")
          end
        end
      end
    end
    
    req.prerequisites.each do |prereq|
      if prereq.class != req.zones[0].class && prereq.class != Request::CLASS_NONE && prereq.class != Request::CLASS_ANY
        raise FormErr.new("Bad prereq: class unknown.")
      end
    end
    
    # update
    
    req.updates.each do |update|
      unless [ req.zones[0].class, Request::TYPE_ANY, Request::TYPE_NONE ].include?(update.class)
        raise FormErr.new("Bad update: class is neigther zone's class, ANY, nor NONE.")
      end
      unless update.name.end_with?(req.zones[0].name)
        raise NotZone.new("Bad update: name not match with zone's name.")
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
          raise FormErr.new("Bad update: unknown type: #{update.type}.")
        end
      end
      if update.class == Request::CLASS_ANY || update.class == Request::CLASS_NONE
        unless update.ttl == 0
          raise FormErr.new("Bad update: TTL != 0.")
        end
      end
      if update.class == Request::CLASS_ANY
        unless update.rdata.length == 0
          raise FormErr.new("Bad update: rdata not empty.")
        end
        case update.type
        when Request::TYPE_A
        when Request::TYPE_AAAA
        when Request::TYPE_PTR
        when Request::TYPE_DHCID
        else
          raise FormErr.new("Bad update: unknown type: #{update.type}")
        end
      end
    end
    
    req.updates.each do |update|
      if update.class == req.zones[0].class
        replaced = false
        data[:records].each do |rr|
          if rr[:name] == update.name && rr[:type] == update.type && rr[:rdata] == update.rdata
            Log.info "Replace RR with: '#{update.name}', #{update.type}, #{update.ttl}, #{update.rdata}"
            rr[:ttl] = update.ttl
            rr[:timestamp] = now
            replaced = true
          end
        end
        unless replaced
          Log.info "Add RR: '#{update.name}', #{update.type}, #{update.ttl}, #{update.rdata}"
          rr = {
            name: update.name,
            type: update.type,
            ttl: update.ttl,
            rdata: update.rdata,
            timestamp: now,
          }
          data[:records] << rr
        end
      end
      if update.class == Request::CLASS_ANY && update.type == Request::TYPE_ANY
        unless update.name == req.zones[0].name
          Log.info "Delete name: '#{update.name}'"
          data[:records] = data[:records].select{ |rr|
            rr[:name] != update.name
          }
        end
      end
      if update.class == Request::CLASS_ANY && update.type != Request::TYPE_ANY
        unless update.name == req.zones[0].name
          Log.info "Delete RRset: '#{update.name}', #{update.type}"
          data[:records] = data[:records].select{ |rr|
            !(rr[:name] == update.name && rr[:type] == update.type)
          }
        end
      end
      if update.class == Request::CLASS_NONE
        data[:records] = data[:records].select{ |rr|
          Log.info "Delete RR: '#{update.name}', #{update.type}, #{update.rdata}"
          !(rr[:name] == update.name && rr[:type] == update.type && rr[:rdata] == update.rdata)
        }
      end
    end
    
    # response
    
    @data = data_alter
    Log.debug @data
    
    update_zone_files
    save_data
    
    res = [
      (req.id >> 8) & 0xff, req.id & 0xff,
      0x80 | Request::OPCODE_UPDATE << 3, 0,
      0, 0,
      0, 0,
      0, 0,
      0, 0,
    ]
    res = sign_tsig(res, req, tsig)
    # sa=[ AF_INET/INET6, port, hostname, host_ipaddr ]
    return res
    Log.debug "OK."
    
  rescue => e
    if e.is_a?(RCode)
      Log.send(e.level, "#{e.to_s} -> #{e.class.to_s.upcase}")
      Log.send(e.level, e.backtrace.join("\n"))
    else
      Log.err e.to_s
      Log.err e.backtrace.join("\n")
    end
    
    res = [
      (req.id >> 8) & 0xff, req.id & 0xff,
      0x80 | Request::OPCODE_UPDATE << 3, e.is_a?(RCode) ? e.code : Request::RCODE_SERVFAIL,
      0, 0,
      0, 0,
      0, 0,
      0, 0,
    ]
    if tsig
      res = sign_tsig(res, req, tsig)
    else
      res = res.pack('C*')
    end
    return res
  end
  
end

raise 'Config file not specified.' unless ARGV[0]

Log.info 'Starting ddns-nsd.'

load_data(ARGV[0])

# https://80x24.org/misc/20151030-inherit-fds-w-o-sd_listen_fds-in-pure@ruby/
# see the sd_listen_fds(3) manpage for details
sd_pid, sd_fds = ENV.values_at('LISTEN_PID', 'LISTEN_FDS')
if sd_pid.to_i == $$ # n.b. $$ can never be zero
  # 3 = SD_LISTEN_FDS_START
  socks = []
  (3...(3 + sd_fds.to_i)).each do |fd|
    s = Socket.for_fd(fd)
    la = s.local_address
    case la.socktype
    when Socket::SOCK_STREAM
      socks << TCPServer.for_fd(fd)
    when Socket::SOCK_DGRAM
      socks << UDPSocket.for_fd(fd)
    end
  end
elsif @listen
  socks = []
  @listen.each do |listen|
    if listen =~ /\A([\d.]+):(\d+)\z/
      sock = UDPSocket.new
      sock.bind($1, $2.to_i)
      socks << sock

      sock = TCPServer.new($1, $2.to_i)
      socks << sock
    elsif listen =~ /\A\[([0-9A-Fa-f:]+)\]:(\d+)\z/
      sock = UDPSocket.new(Socket::AF_INET6)
      sock.bind($1, $2.to_i)
      socks << sock

      sock = TCPServer.new($1, $2.to_i)
      socks << sock
    else
      raise "Bad listen: #{listen}" unless listen =~ /\A([^:]+):(\d+)\z/
    end
  end
end

def process_udp(sock)
  data, sa = sock.recvfrom(65536)
  res = process_packet data
  # sa=[ AF_INET/INET6, port, hostname, host_ipaddr ]
  sa = Addrinfo.getaddrinfo(sa[3], sa[1], sa[0], :DGRAM)[0] if sa.is_a?(Array)
  sock.send(res, 0, sa)
end

def read_from_socket(sock, len)
  buf = ''
  while buf.length < len
    b = sock.read(len - buf.length)
    return nil if b == '' || b.nil?
    buf += b
  end
  Log.debug("buf.lenth=#{buf.length}")
  return buf
end

def process_tcp(sock)
  while true
    lendata = read_from_socket(sock, 2)
    return if lendata.nil?
    len = lendata.unpack('n')[0]
    data = read_from_socket(sock, len)
    return if data.nil?
    res = process_packet data
    sock.write([res.length].pack('n'))
    sock.write(res)
  end
end

while true
  Log.debug "recving..."
  while true
    # nsd を reload する必要があるなら、timeout を 1秒に設定。
    # 1秒間に何も来ずに timeout すれば、reload する。
    # 1秒の間に何か来たら、それを処理し、またその後 1秒待つ。
    rs, ws = IO.select(socks, [], [], @need_reload ? 1 : nil)
    break if rs
    
    Log.info('reloading nsd.')
    unless system(@restart_nsd)
      Log.error "Failed to reload nsd."
    else
      @need_reload = false
    end
  end
  
  rs.each do |sock|
    s = nil
    begin
      if sock.is_a?(UDPSocket)
        process_udp sock
      elsif sock.is_a?(TCPServer)
        s = sock.accept
        process_tcp s
      else
        raise "Unknown socket class: #{sock.class}"
      end
    rescue Exception => e
      Log.err e.to_s
      Log.err e.backtrace
    ensure
      if s
        s.close
      end
    end
  end
end
