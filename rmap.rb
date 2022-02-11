require 'optparse'
require 'nmap/program'
require 'nmap/xml'
require 'colorize'
def banner
%q(
                                                 
         

        8888888b.                                       
        888   Y88b                                      
        888    888                                      
        888   d88P 88888b.d88b.   8888b.  88888b.       
        8888888P"  888 "888 "88b     "88b 888 "88b      
        888 T88b   888  888  888 .d888888 888  888      
        888  T88b  888  888  888 888  888 888 d88P      
        888   T88b 888  888  888 "Y888888 88888P"       
                                          888           
                                          888           
                                          888           
          
      
                        
   
 )
end
puts banner.red
o = {
  "osprint": true,
  "service": true,
  "outfile": "scan.xml",
  "ports": [20,21,22,23,25,80,110,443,512,522,8080,1080],
  "xml":    nil,
  "spoof_mac": nil
}
OptionParser.new do |parser|
 parser.on('--syn [[SYN]', "SYN scan") do |m|
  o[:syn] = M
 end
 parser.on('--outfile [OUTFILE]', "The outfile file. By default the file is named: scan.xml") do |m|
  o[:outfile] = m
 end
 parser.on('--osprint', TrueClass, "os fingerprint scan") do |m|
  o[:osprint] = false
 end
 parser.on("--service", TrueClass, "Perform a Service scan") do |m|
  o[:service] = false
 end
 parser.on("--target [TARGET]", "Target IP - ( basic scan )") do |m|
  o[:target] = m
 end
 parser.on("--ports", Array, "The ports it should scan") do |m|
  o[:ports] = m
 end
 parser.on('--xml [XML]', "Parse & print out the content of the XML file.") do |m|
  o[:xml] = m
 end
 parser.on('--banner [BANNER]', "Banner scan the target") do |m|
  o[:banner]    = m
 end
 parser.on('--wordpress [WORDPRESS]', "Wordpress enum") do |m|
  o[:wordpress] = m
 end
 parser.on('--phpversion [PHPVERSION]', "Attempt to get get what PHP version the site is running.") do |m|
  o[:wordpress] = m
 end
 parser.on('--btcinfo [BTCINFO]', "Get information about a Bitcoin node") do |m|
  o[:btcinfo] = m
 end
 parser.on('--dnsbrute [DNSBRUTE', "DNS brute a domain.") do |m|
    o[:dnsbrute] = m
 end
 parser.on('--wpusers [WPUSERS]', "Find Wordpress users") do |m|
    o[:wpusers] = m
 end
 parser.on('--affiliateid [AFFILIATEID]', "Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon Associates, etc.) from a web page. These can be used to identify pages with the same owner.") do |m|
 o[:affiliateid] = m
 end
 parser.on('--spoofmac [SPOOFMAC]', "spoof Mac") do |m|
    o[:spoofmac] = m
 end
 parser.on('--ack [ACK]', "Perform a ACK scan") do |m|
    o[:ack] = m
 end
 parser.on('--udp [UDP]', "Perform a UDP scan") do |m|
    o[:udp] = m
 end
 parser.on('--connect [CONNECT]', "Perform a CONNECT scan") do |m|
    o[:connect] = m
 end
 parser.on('--null [NULL]', "Perform a Null scan") do |m|
    o[:null] = m
 end
 parser.on('--fin [FIN]', "Perform a fin scan") do |m|
    o[:fin] = m
 end
 parser.on('--xmas [XMAS]', "Perform a XMAS scan") do |m|
    o[:xmas] = m
 end
 parser.on('--window [WINDOW]', "Perform a window scan") do |m|
    o[:window] = m
 end
 parser.on('--maimon [MAIMON]', "Perform a maimon scan") do |m|
    o[:maimon] = m
 end
 parser.on('--echo [ECHO]', "Perform a ECHO scan") do |m|
    o[:echo] = m
 end
 parser.on('--idle [IDLE]', "Perform a IDLE scan") do |m|
    o[:idle] = m
 end
end.parse!
def scan(nse: "", target: "", out: "", port: nil, spoof_mac: nil)
  Nmap::Program.scan do |nmap|
    nmap.script          = nse
    nmap.targets         = target
    nmap.skip_discovery  = true
    nmap.xml             = out
    nmap.spoof_mac       = spoof_mac if !spoof_mac.nil?
    nmap.ports           = port.to_i if !port.nil?
  end
end
def port_scan(ack: false, syn: false, connect:false, udp: false, null: false, fin: false, xmas: false, window: false, maimon: false, echo: false, idle: false, target: "", ports: [], out: "scan.xml", spoof_mac: nil)
    Nmap::Program.scan do |nmap|
        nmap.ack_scan        = ack
        nmap.syn_scan        = syn
        nmap.connect_scan    = connect
        nmap.udp_scan        = udp
        nmap.null_scan       = null
        nmap.fin_scan        = fin
        nmap.xmas_scan       = xmas
        nmap.window_scan     = window
        nmap.maimon_scan     = maimon
        nmap.idle_scan       = idle
        nmap.service_scan    = true
        nmap.os_fingerprint  = true
        nmap.xml             = out
        nmap.verbose         = true
        nmap.ports           = ports
        nmap.targets         = target
        nmap.spoof_mac       = spoof_mac if !spoof_mac.nil?
    end 
end
if !o[:target].nil?
  Nmap::Program.scan do |nmap|
    nmap.syn_scan        = o[:syn]
    nmap.service_scan    = o[:service]
    nmap.os_fingerprint  = o[:osprint]
    nmap.xml             = o[:outfile]
    nmap.verbose         = true
    nmap.ports           = o[:ports]
    nmap.targets         = o[:target]
  end
end
if !o[:xml].nil?
  Nmap::XML.new(o[:xml]) do |xml|
    xml.each_host do |host|
      puts "[#{host.ip}]"
      host.scripts.each do |name,output|
        output.each_line { |line| puts "  #{line}" }
      end
      host.each_port do |port|
        puts "  [#{port.number}/#{port.protocol}]"
        port.scripts.each do |name,output|
          puts "    [#{name}]"
          output.each_line { |line| puts "      #{line}" }
        end
      end
    end
  end
end
scan(nse: 'banner', target: o[:banner], out: o[:outfile], spoof_mac: o[:spoofmac]) if !o[:banner].nil?

scan(nse: "http-wordpress-enum", target: o[:wordpress], out: o[:outfile]) if !o[:wordpress].nil?

scan(nse: "http-php-version", target: o[:phpversion], out: o[:outfile]) if !o[:phpversion].nil?

scan(nse: "bitcoin-info", target: o[:btcinfo], out: o[:outfile], port: 8333) if !o[:btcinfo].nil?

scan(nse: "dns-brute", target: o[:dnsbrute], out: o[:outfile]) if !o[:dnsbrute].nil?
    
scan(nse: "http-wordpress-users", target: o[:wpusers], out: o[:outfile]) if !o[:wpusers].nil?

scan(nse: "http-affiliate-id", target: o[:affiliateid], out: o[:outfile]) if !o[:affiliateid].nil?

port_scan(ack: true, target: o[:ack], spoof_mac: o[:spoofmac]) if !o[:ack].nil?

port_scan(syn: true, target: o[:syn], spoof_mac: o[:spoofmac]) if !o[:syn].nil?

port_scan(connect: true, target: o[:connect], spoof_mac: o[:spoofmac]) if !o[:connect].nil?

port_scan(udp: true, target: o[:udp], spoof_mac: o[:spoofmac]) if !o[:udp].nil?

port_scan(connect: true, target: o[:connect], spoof_mac: o[:spoofmac]) if !o[:connect].nil?

port_scan(null: true, target: o[:null], spoof_mac: o[:spoofmac]) if !o[:null].nil?

port_scan(fin: true, target: o[:fin], spoof_mac: o[:spoofmac]) if !o[:fin].nil?

port_scan(xmas: true, target: o[:xmas], spoof_mac: o[:spoofmac]) if !o[:xmas].nil?

port_scan(window: true, target: o[:window], spoof_mac: o[:spoofmac]) if !o[:window].nil?

port_scan(maimon: true, target: o[:maimon], spoof_mac: o[:spoofmac]) if !o[:maimon].nil?

port_scan(echo: true, target: o[:echo], spoof_mac: o[:spoofmac]) if !o[:echo].nil?

port_scan(idle: true, target: o[:idle], spoof_mac: o[:spoofmac]) if !o[:idle].nil?