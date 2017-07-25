#!/usr/bin/env ruby

require 'socket'

def dump(ary, beg, len)
  print "---------------------------------\n"
  print "[i=0x#{'%x' % beg}, len=#{len}]\n"
  len.times do |i|
    print ' %02x' % ary[beg + i]
    print "\n" if i % 16 == 15
  end
  print "\n" unless len % 16 == 0
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
    dump(data, 0, data.length)
    id = data[0] << 8 | data[1]
    puts "ID=0x#{"%04x" % id}"
    
    vals = data[2] << 8 | data[3]
    qr = (vals >> 15) & 1
    opcode = (vals >> 11) & 0x0f
    z = (vals >> 4) & 0x7f
    rcode = (vals >> 0) & 0x0f
    
    zocount = data[4] << 8 | data[5]
    prcount = data[6] << 8 | data[7]
    upcount = data[8] << 8 | data[9]
    adcount = data[10] << 8 | data[11]
    puts "QR=#{qr} (#{qr == 0 ? 'req' : 'res'})"
    puts "Opcode=0x#{'%x' % opcode} (#{opcode == 5 ? 'UPDATE' : '??????'})"
    puts "Z=0x#{'%02x' % z} (#{z == 0 ? 'ok' : 'unknown'})"
    puts "RCODE=0x#{'%x' % rcode}"
    puts "ZOCOUNT=#{zocount} (#zone)"
    puts "PRCOUNT=#{prcount} (#prereq)"
    puts "UPCOUNT=#{upcount} (#update)"
    puts "ADCOUNT=#{adcount} (#additional)"
    
    i = 12
    dump(data, i, data.length - i)
    # RFC 1035 を見た方が良い
    zocount.times do
      puts "Zone:------------------------------"
      zname = ''
      while data[i] != 0
        data[i].times do
          i += 1
          zname += '%c' % data[i]
        end
        i += 1
        zname += '.'
      end
      i += 1
      puts "ZNAME='#{zname}'"
      
      ztype = data[i] << 8 | data[i + 1]
      i += 2
      zclass = data[i] << 8 | data[i + 1]
      i += 2
      puts "ZTYPE=#{ztype}"   # must be SOA.
      puts "ZCLASS=#{zclass}" # zone's class.
      
      dump(data, i, data.length - i)
    end
    
    prcount.times do
      puts "Prereq:------------------------------"
      rrname = ''
      j = nil
      while j.nil? && data[i] != 0
        if (data[i] & 0xc0) != 0x00
          j = (data[i] & ~0xc0) << 8 | data[i + 1]
          i += 2
        else
          data[i].times do
            i += 1
            rrname += '%c' % data[i]
          end
          i += 1
          rrname += '.'
        end
      end
      unless j.nil?
        while data[j] != 0
          if (data[j] & 0xc0) != 0x00
            j = (data[j] & ~0xc0) << 8 | data[j + 1]
          else
            data[j].times do
              j += 1
              rrname += '%c' % data[j]
            end
            j += 1
            rrname += '.'
          end
        end
      end
      
      rrtype = data[i] << 8 | data[i + 1]
      i += 2
      rrclass = data[i] << 8 | data[i + 1]
      i += 2
      rrttl = data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3]
      i += 4
      rrrdlength = data[i] << 8 | data[i + 1]
      i += 2
      rrrdata = data[i...i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
    end
    
    upcount.times do
      puts "Update:------------------------------"
      rrname = ''
      j = nil
      while j.nil? && data[i] != 0
        if (data[i] & 0xc0) != 0x00
          j = (data[i] & ~0xc0) << 8 | data[i + 1]
          i += 2
        else
          data[i].times do
            i += 1
            rrname += '%c' % data[i]
          end
          i += 1
          rrname += '.'
        end
      end
      unless j.nil?
        while data[j] != 0
          if (data[j] & 0xc0) != 0x00
            j = (data[j] & ~0xc0) << 8 | data[j + 1]
          else
            data[j].times do
              j += 1
              rrname += '%c' % data[j]
            end
            j += 1
            rrname += '.'
          end
        end
      end
      
      rrtype = data[i] << 8 | data[i + 1]
      i += 2
      rrclass = data[i] << 8 | data[i + 1]
      i += 2
      rrttl = data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3]
      i += 4
      rrrdlength = data[i] << 8 | data[i + 1]
      i += 2
      rrrdata = data[i...i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
    end
    
    adcount.times do
      puts "Additional:------------------------------"
      rrname = ''
      j = nil
      while j.nil? && data[i] != 0
        if (data[i] & 0xc0) != 0x00
          j = (data[i] & ~0xc0) << 8 | data[i + 1]
          i += 2
        else
          data[i].times do
            i += 1
            rrname += '%c' % data[i]
          end
          i += 1
          rrname += '.'
        end
      end
      if j.nil?
        i += 1
      else
        while data[j] != 0
          if (data[j] & 0xc0) != 0x00
            j = (data[j] & ~0xc0) << 8 | data[j + 1]
          else
            data[j].times do
              j += 1
              rrname += '%c' % data[j]
            end
            j += 1
            rrname += '.'
          end
        end
      end
      
      rrtype = data[i] << 8 | data[i + 1]
      i += 2
      rrclass = data[i] << 8 | data[i + 1]
      i += 2
      rrttl = data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3]
      i += 4
      rrrdlength = data[i] << 8 | data[i + 1]
      i += 2
      rrrdata = data[i...i + rrrdlength]
      i += rrrdlength
      
      puts "RR name=#{rrname}"
      puts "RR type=#{rrtype}"
      puts "RR class=#{rrclass}"
      puts "RR ttl=#{rrttl}"
      puts "RR rdlength=#{rrrdlength}"
      puts "RR rdata=#{rrrdata}"
      
      dump(data, i, data.length - i)
    end
    
  end
end

Thread.new do
  try_tcp
end
try_udp
