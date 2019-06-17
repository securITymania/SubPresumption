# SubPresumption v1.0
#### This is a just basic subdomain takeover enumeration tool. This tool reduces the time spend to check subdomain takeover for the BugBounty hunters. The tool shows the CNAME records of the 404 subdomains and gives an idea to the Bounter.

## Features 
  * __Multi Thead Requests__
  * __Get subdomains from the virustotal API__
  * __You can feed text file contains subdomains__
  
## Configuration
1. First get the virus total API key by signup on the virustotal.com
2. Export virustotal API key in VIRUS_TOTAL_API_KEY variable via .profile file
   ```
   cd ~
   vi .profile
   export VIRUS_TOTAL_API_KEY="************YOUR VIRUS TOTAL API KEY************"
   ```
3. Restart the terminal session
4. Run ``` pip3 install -r requirements.txt ```

## Usage:
```
Usage: SubPresumption.py [argument] [Textfile]  Text file contains subdomains
       SubPresumption.py [argument] [hostname]   Target hostname (By default tool gets the subdomains from virus-total API)

Arguments
     -d        Supply Target main Domain
     -l        Supply Textfile as input

Usage: python3 ./SubPresumption.py -d example.com
       python3 ./SubPresumption.py -l subdomains.txt 
```
## ScreenShots
