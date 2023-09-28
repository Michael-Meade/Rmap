# frozen_string_literal: true

require 'optparse'
require 'nmap/command'
require 'nmap/xml'
require 'colorize'
o = {
  "syn": false,
  "ack": false,
  "null": false,
  "list": false,
  "fin": false,
  "xmas": false,
  "window": false,
  "maimon": false,
  "arp_ping": false,
  "udp": false,
  "ping": false,
  "normal": 'out.txt'
}
OptionParser.new do |parser|
  parser.on('--syn', TrueClass, 'SYN scan') { |m| o[:syn] = m }
  parser.on('--ack', TrueClass, 'ACK scan') { |m| o[:ack] = m }
  parser.on('--null', TrueClass, 'null scan') { |m| o[:null] = m }
  parser.on('--list', TrueClass, 'list scan') { |m| o[:list] = m }
  parser.on('--fin', TrueClass, 'fin scan') { |m| o[:fin] = m }
  parser.on('--xmas', TrueClass, 'xmas scan') { |m| o[:xmas] = m }
  parser.on('--window', TrueClass, 'window scan') { |m| o[:window] = m }
  parser.on('--maimon', TrueClass, 'maimon scan') { |m| o[:maimon] = m }
  parser.on('--arp-ping', TrueClass, 'arp ping') { |m| o[:arp_ping] = m }
  parser.on('--udp', TrueClass, 'Udp scan') { |m| o[:udp] = m }
  parser.on('--normal [NORMAL]', 'Output normal') { |m| o[:normal] = m }
  parser.on('--ping',  TrueClass, 'ping scan') { |m| o[:ping] = m }
  parser.on('--ip IP', 'IP') { |m| o[:ip] = m }
end.parse!

Nmap::Command.run do |nmap|
  nmap.syn_scan = o[:syn]
  nmap.targets       = o[:ip]
  nmap.ack_scan      = o[:ack]
  nmap.null_scan     = o[:null]
  nmap.list          = o[:list]
  nmap.fin_scan      = o[:fin]
  nmap.xmas_scan     = o[:xmas]
  nmap.window_scan   = o[:window]
  nmap.maimon_scan   = o[:maimon]
  nmap.arp_ping      = o[:arp_ping]
  nmap.udp_scan      = o[:udp]
  nmap.output_normal = o[:normal]
  nmap.ping          = o[:ping]
end
