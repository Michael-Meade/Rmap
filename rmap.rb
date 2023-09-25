require 'optparse'
require 'nmap/command'
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
  "outnormal": "out.txt",
  "ports": [20,21,22,23,25,80,88,110,111,115,118,137,139,143,156,161,194,220,464,465,601,902,903,636,749,750,751,981,990,992,443,512,522,8080,8008,1080,8333,18080,28080,18081,28081,22556,11626],
  "xml":    nil,
  "spoof_mac": nil
}
OptionParser.new do |parser|
 parser.on('--syn [SYN]', "SYN scan") { |m| o[:syn] = m }

 parser.on('--outnormal [OUTNORMAL]', "The outnormal file.") { |m| o[:outnormal] = m }

 parser.on('--outfile [OUTFILE]', "The outfile file. By default the file is named: scan.xml") { |m| o[:outfile] = m }

 parser.on('--osprint', TrueClass, "os fingerprint scan") { |m| o[:osprint] = false }

 parser.on("--service", TrueClass, "Perform a Service scan") { |m| o[:service] = false }

 parser.on("--target [TARGET]", "Target IP - ( basic scan )") { |m| o[:target] = m }

 parser.on("--ports", Array, "The ports it should scan") { |m| o[:ports] = m }

 parser.on('--xml [XML]', "Parse & print out the content of the XML file.") { |m| o[:xml] = m }
 
 parser.on('--banner [BANNER]', "Banner scan the target") { |m| o[:banner]  = m }

 parser.on('--wordpress [WORDPRESS]', "Wordpress enum") { |m| o[:wordpress] = m }

 parser.on('--phpversion [PHPVERSION]', "Attempt to get get what PHP version the site is running.") { |m| o[:phpversion] = m }

 parser.on('--btcinfo [BTCINFO]', "Get information about a Bitcoin node") { |m| o[:btcinfo] = m}

 parser.on('--dnsbrute [DNSBRUTE', "DNS brute a domain.") { |m| o[:dnsbrute] = m }

 parser.on('--wpusers [WPUSERS]', "Find Wordpress users") { |m| o[:wpusers] = m }

 parser.on('--affiliateid [AFFILIATEID]', "Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon Associates, etc.) from a web page. These can be used to identify pages with the same owner.") { |m| o[:affiliateid] = m }

 parser.on('--spoofmac [SPOOFMAC]', "spoof Mac") { |m| o[:spoofmac] = m }

 parser.on('--ack [ACK]', "Perform a ACK scan") { |m|  o[:ack] = m }

 parser.on('--udp [UDP]', "Perform a UDP scan") { |m| o[:udp] = m } 

 parser.on('--connect [CONNECT]', "Perform a CONNECT scan") { |m| o[:connect] = m }

 parser.on('--null [NULL]', "Perform a Null scan") { |m| o[:null] = m }

 parser.on('--fin [FIN]', "Perform a fin scan") { |m| o[:fin] = m }

 parser.on('--xmas [XMAS]', "Perform a XMAS scan") { |m| o[:xmas] = m }

 parser.on('--window [WINDOW]', "Perform a window scan") { |m| o[:window] = m }

 parser.on('--maimon [MAIMON]', "Perform a maimon scan") { |m| o[:maimon] = m }

 parser.on('--list [LIST]', "Perform a list scan") { |m| o[:list] = m }

 parser.on('--echo [ECHO]', "Perform a ECHO scan") { |m| o[:echo] = m }

 parser.on('--idle [IDLE]', "Perform a IDLE scan") { |m| o[:idle] = m }

 parser.on('--openredirect [OPENREDIRECT]', "Open redirect scan") { |m| o[:openredirect] = m }

 parser.on('--extractdomains [EXTRACTDOMAINS]', "Extract domains from the xml file. Ran after --dnsbrute.") { |m| o[:extractdomains] = m}

 parser.on('--wp [WP]', "Run a bunch of different Wordpress scans") { |m| o[:wp] = m}

 parser.on('--smtpusers [SMTPUSERS]', "Attempts to enumerate the users on a SMTP server ") { |m| o[:smtpusers] = m}

 parser.on('--smtpbrute [SMTPBRUTE]', "Performs brute force password auditing against SMTP servers") { |m| o[:smtpbrute] = m}

 parser.on('--phpselfxss [PHPSELFXSS]', "This script crawls the webserver to create a list of PHP files and then sends an attack vector/probe to identify PHP_SELF  cross site scripting vulnerabilities") { |m| o[:phpselfxss] = m}

parser.on('--vncinfo [VNCINFO]', "Queries a VNC server for its protocol version and supported security types.") { |m| o[:vncinfo] = m}

parser.on('--enumsmb [ENUMSMB]', "Attempts to list shares") { |m| o[:enumsmb] = m}

parser.on('--apachestatus [APACHESTATUS]', "Attempts to retrieve the server-status page for Apache webservers that have mod_status enabled.") { |m| o[:apachestatus] = m}

parser.on('--drupalenum [DRUPALENUM]', "Enumerates the installed Drupal modules/themes by using a list of known modules and themes.") { |m| o[:drupalenum] = m}

parser.on('--normal',TrueClass, "save output as normal") { |m| o[:normal] = m}

parser.on('--drupalusers [DRUPALUSERS]', "Enumerates Drupal users by exploiting an information disclosure vulnerability in Views, Drupal's most popular module.") { |m| o[:drupalusers] = m}

parser.on('--httpenum [HTTPENUM]', "Enumerates directories used by popular web applications and servers") { |m| o[:httpenum] = m}

parser.on('--grep [GREP]', "save scan greppeable") { |m| o[:grep] = m}

parser.on('--arp [ARP]', "arp scan") { |m| o[:arp] = m}

end.parse!

def scan(nse: "", target: "", out: "#{target}.xml", ports: nil, spoof_mac: nil, outnormal: "text.txt", target_file: "",)
  Nmap::Command.run do |nmap|
    nmap.output_normal   = "t.txt"
    nmap.script          = nse
    nmap.targets         = target
    nmap.skip_discovery  = true
    nmap.output_xml      = out
    nmap.spoof_mac       = spoof_mac if !spoof_mac.nil?
    nmap.ports           = ports.to_i if !ports.nil?
    nmap.target_file     = target_file
  end
end
def port_scan(ack: false, syn: false, connect:false, target_file: "", list: false, udp: false, null: false, fin: false, xmas: false, window: false, maimon: false, echo: false, idle: false, target: "", ports: [20,21,22,23,25,80,88,110,111,115,118,137,139,143,156,161,194,220,464,465,601,902,903,636,749,750,751,981,990,992,443,512,522,8080,8008,1080,8333,18080,28080,18081,28081,22556,11626], out: "scan.xml", spoof_mac: nil, outnormal: "out.txt")
    Nmap::Command.run do |nmap|
        nmap.ack_scan        = ack
        nmap.output_xml      = out
        nmap.syn_scan        = syn
        nmap.connect_scan    = connect
        nmap.udp_scan        = udp
        nmap.null_scan       = null
        nmap.fin_scan        = fin
        nmap.xmas_scan       = xmas
        nmap.window_scan     = window
        nmap.maimon_scan     = maimon
        nmap.skip_discovery = false
        nmap.output_normal = outnormal
        nmap.verbose         = true
        nmap.ports           = ports
        nmap.targets         = target
        nmap.target_file     = target_file
        nmap.spoof_mac       = spoof_mac if !spoof_mac.nil?
    end 
end
def host_discovery(list: false, target: "", target_file: "", normal: false, grep: "grep_scan.txt", arp: false, ports: [80,443])
  Nmap::Command.run do |nmap|
    nmap.list            = list
    nmap.targets         = target
    nmap.output_normal   = "list_scan.txt"
    nmap.output_grepable = grep
    nmap.arp_ping        = arp
    nmap.target_file     = target_file
    nmap.udp_discovery   = ports
  end
end
def extract_domains(txt,o)
  out =[]
  read = File.read(txt)
  read.split("DNS Brute-force hostnames: ")[1].split("-").each do |l|
    begin
      subdomain = l.split("|")[1].strip.gsub("_", "").strip
      if !out.include?(subdomain)
        out << subdomain
      end
    rescue => e
    
    end
  end
    File.open("#{o[:dnsbrute]}-subdomains.txt", 'w') { |f| f.write(out.join("\n")) }

  out =[]
  read = File.read(txt)
  begin
    read.split("DNS Brute-force hostnames: ")[1].split("-").each do |l|
        ips = l.split("-")[0].strip.split("|")[0].gsub("|", "").strip.split("\n\n#")[0]
        if !out.include?(ips)
          out << ips
        end
    end
  rescue
  end
   out = out.compact
   File.open("#{o[:dnsbrute]}-ips.txt", 'w') { |f| f.write(out.join("\n")) }
end
def wp(domain)
  scan(nse: "dns-brute", target: o[:dnsbrute], outnormal: o[:outnormal]) if !o[:dnsbrute].nil?
  scan(nse: "http-wordpress-enum", target: domain, out: "#{domain}-wp-enum.xml")
  scan(nse: "http-wordpress-users", target: domain, out: "#{domain}-wp-users.xml")
  scan(nse: "http-wordpress-brute", target: domain, out: "#{domain}-wp-brute.xml")
end
if !o[:target].nil?
  Nmap::Command.run do |nmap|
    nmap.syn_scan        = o[:syn]
    nmap.service_scan    = o[:service]
    nmap.os_fingerprint  = o[:osprint]
    nmap.output_xml           = o[:outfile]
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

scan(nse: "dns-brute", target: o[:dnsbrute], outnormal: o[:outnormal]) if !o[:dnsbrute].nil?
    
scan(nse: "http-wordpress-users", target: o[:wpusers], out: o[:outfile]) if !o[:wpusers].nil?

scan(nse: "http-affiliate-id", target: o[:affiliateid], out: o[:outfile]) if !o[:affiliateid].nil?

scan(nse: "http-open-redirect", target: o[:openredirect], out: o[:outfile]) if !o[:openredirect].nil?

scan(nse: "smtp-enum-users", target: o[:smtpusers], out: o[:outfile]) if !o[:smtpusers].nil?

scan(nse: "smtp-brute", target: o[:smtpbrute], out: o[:outfile]) if !o[:smtpbrute].nil?

scan(nse: "http-phpself-xss", target: o[:phpselfxss], out: o[:outfile], port: [443, 80]) if !o[:phpselfxss].nil?

scan(nse: "vnc-info", target: o[:vncinfo], out: o[:outfile]) if !o[:vncinfo].nil?

scan(nse: "smb-enum-shares", target: o[:enumsmb], out: o[:outfile]) if !o[:enumsmb].nil?

scan(nse: "http-apache-server-status", target: o[:apachestatus], out: o[:outfile]) if !o[:apachestatus].nil?

scan(nse: "http-drupal-enum", target: o[:drupal], out: o[:outfile]) if !o[:drupal].nil?

scan(nse: "http-drupal-enum-users", target: o[:drupalusers], out: o[:outfile]) if !o[:drupalusers].nil?

scan(nse: "http-enum", target: o[:httpenum], out: o[:outfile]) if !o[:httpenum].nil?

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

host_discovery(list: true, target: o[:list]) if !o[:list].nil?

host_discovery(arp: true, target: o[:arp]) if !o[:arp].nil?


wp(o[:wp]) if !o[:wp].nil?

extract_domains(o[:extractdomains], o) if !o[:extractdomains].nil?