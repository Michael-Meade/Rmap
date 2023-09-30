<h1 align="center">Rmap</h1>
<div align="center">
  
**[About](https://github.com/Michael-Meade/Rmap/blob/main/README.md#About) • 
[Installing gems](https://github.com/Michael-Meade/Rmap/blob/main/README.md#Installing-gems) • 
[Installation](https://github.com/Michael-Meade/Rmap/blob/main/README.md#Installation) • 
[Help](https://github.com/Michael-Meade/Rmap/blob/main/README.md#Help-Menu) •
[License](https://github.com/Michael-Meade/Rmap/blob/main/README.md#License)**
</div>





# About
This tool uses <a href="https://github.com/sophsec/ruby-nmap"> ruby-nmap gem</a>. Nmap must be installed on the computer for it to work. It will save the results into a xml file. The tool can parse the xml file & print out the results.

This tool can perform:
* Syn scan
* idle scan
* ack scan
* udp scan
* connect scan
* null scan
* fin scan
* xmas scan 
* window scan
* maimon scan
* echo scan
* spoof mac address

The tool is also able to use the following NSE scripts:
* banner
* http-wordpress-enum
* http-php-version
* bitcoin-info
* dns-brute
* http-wordpress-users
* http-affiliate-id
* dns brute

# Installing-gems
```ruby
gem install colorize
gem install ruby-nmap
```

# Installation
```ruby
sudo apt-get install nmap
```
If you are on windows use this link: https://nmap.org/download.html

# Help-Menu

## Help menu
```ruby
ruby rmap.rb --H
```
### OS fingerprint
```
 sudo ruby nmap.rb --ip yahoo.com --normal os_scan_yahoo.txt --os
```
## Spoof Mac
```ruby
sudo ruby nmap.rb --idle 127.0.0.1 --spoofmac 00:11:22:33:44:55
```

## Parse & print out xml file
```ruby
ruby nmap.rb --xml scan.xml
```
## Get information about A bitcoin node
```ruby
ruby nmap.rb --btcinfo 91.12.218.35
```

## Php version
```ruby
ruby rmap.rb --phpversion example.com
```
### DNS brute
```ruby
ruby nmap.rb --script dns-brute --ip google.com --normal google.com.txt
```
### xmas scan
```ruby
sudo ruby nmap.rb --ip 192.168.1.* --xmas --normal xmas.txt
```
### Extract Subdomains and IPS
```ruby
ruby nmap.rb --extractdomains google.com.txt
ruby nmap.rb --script dns-brute --ip yahoo.net --normal yahoo.txt --extractdomains yahoo.txt
ruby nmap.rb --targetfile yahoo.txt-ips.txt --normal service_scan_yahoo.txt --service
```
### Wordpress
```ruby
ruby rmap.rb --wp google.com
```
### Arp ping
```ruby
sudo ruby nmap.rb --ip 192.168.1.* --arp-ping
```
### Null scan
```ruby
ruby nmap.rb --ip 192.168.1.* --null
```
### List scan saving output
```ruby
sudo ruby rmap.rb --list --ip 192.168.1.1/24 --normal tttt.txt
```
Requires sudo permissions

# License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

