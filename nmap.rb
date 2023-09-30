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
  "dnsbrute": false,
  "ping": false,
  "service": false,
  "ipv6": false,
  "os": false,
  "random": 10
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
  parser.on('--ping', TrueClass, 'ping scan') { |m| o[:ping] = m }
  parser.on('--script [SCRIPT]', 'Scripts') { |m| o[:script] = m }
  parser.on('--service', TrueClass, 'Service scan') { |m| o[:service] = m }
  parser.on('--normal [NORMAL]', 'save output as normal') { |m| o[:normal] = m }
  parser.on('--targetfile [TARGETFILE]', 'Scan from file') { |m| o[:targetfile] = m }
  parser.on('--ipv6', 'Ipv6') { |m| o[:ipv6] = m }
  parser.on('--extractdomains [EXREACTDOMAINS]', 'Extract domains from the file. .') { |m| o[:extractdomains] = m }
  parser.on('--ip IP', 'IP') { |m| o[:ip] = m }
  parser.on('--os', 'OS scan') { |m| o[:os] = m }
  parser.on('--random [RANDOM]', 'geerate random targets') { |m| o[:random] = m }
end.parse!

def extract_domains(o)
  out = []
  read = File.read(o.to_s)
  read.split('DNS Brute-force hostnames: ')[1].split('-').each do |l|
    subdomain = l.split('|')[1].strip.gsub('_', '').strip
    out << subdomain unless out.include?(subdomain)
  rescue StandardError
  end
  File.open("#{o}-subdomains.txt", 'w') { |f| f.write(out.join("\n")) }

  out = []
  read = File.read(o)
  begin
    read.split('DNS Brute-force hostnames: ')[1].split('-').each do |l|
      ips = l.split('-')[0].strip.split('|')[0].gsub('|', '').strip.split("\n\n#")[0]
      out << ips unless out.include?(ips)
    end
  rescue StandardError
  end
  out = out.compact
  File.open("#{o}-ips.txt", 'w') { |f| f.write(out.join("\n")) }
end

Nmap::Command.run do |nmap|
  nmap.syn_scan      = o[:syn]
  nmap.script        = o[:script]
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
  nmap.ipv6          = o[:ipv6]
  nmap.service_scan  =  o[:service]
  nmap.os_fingerprint = o[:os]
  nmap.target_file = o[:targetfile] unless o[:targetfile].nil?
  nmap.random_targets = o[:random] unless o[:random].nil?
end

extract_domains(o[:extractdomains]) unless o[:extractdomains].nil?
