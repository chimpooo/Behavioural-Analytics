import requests
import json
from bs4 import BeautifulSoup
from urllib import parse
from requests.exceptions import HTTPError
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

virustotal_user = ""
virustotal_pass = ""
virustotal_apikey = ""
proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
}
verify_ssl = False
#hash_test = "139a7d6656feebe539b2cb94b0729602f6218f54fb5b7531b58cfe040f180548"
# x-apikey
#endpont_get_report_hash = "https://www.virustotal.com/api/v3/files/{0}"
endpont_get_report_hash = "https://www.virustotal.com/api/v3/collections/{0}"



def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.

#curl --request GET --url https://www.virustotal.com/api/v3/files/84f909f2a044110a830148d98d47351342a2f1c9d5f75e6b8801ff34c9e9fa98 --header 'x-apikey: ----'

#get hash from vx-underground
def get_malware_url_names():
    url_underground = "https://samples.vx-underground.org/samples/Families/REvil/"
    underground_page = requests.get(url_underground)    #, proxies=proxies, verify=verify_ssl)
    soup = BeautifulSoup(underground_page.content, "html.parser")
    hyperlinks = soup.find_all("td", class_="link")
    list_malwares = []
    for hyperlink in hyperlinks:
        hyperlink_info = hyperlink.find('a', href=True)
        malware_url = hyperlink_info['href']
        malware_name = hyperlink_info.contents[0]
        malware_info= malware_name.split(".") #{"name": malware_name}   
        if malware_name != 'Parent directory/':
            list_malwares.append(malware_info[0])         
    return list_malwares

# Press the green button in the gutter to run the script.
# Get the files and collection present the VirusTotal Environment for the hashes fed.
# Store the analysis of the file in JSON format
if __name__ == '__main__':
    print_hi('Malware')
    print("--------------------------------------X-------------------------------------X")
    print("\n")
    virus_total = requests.Session()
    header_request = {"x-apikey": virustotal_apikey}
    current_collection='c879ad5e8de6d4e0a0f2287b6e8ebd9170fb24430ce9cbf4451d3dacf298f237'
    if current_collection is not None:
        print("malware info", current_collection )
        #response_report_hash = virus_total.get(endpont_get_report_hash.format(hash_test),headers=header_request, proxies=proxies, verify=verify_ssl)
        response_report_hash = virus_total.get(endpont_get_report_hash.format(current_collection),headers=header_request, proxies=proxies, verify=verify_ssl)
        print(response_report_hash)
        L = response_report_hash.text
        # Writing to file
        with open("Sample_vt_collection.json", "w") as file1:
            # Writing data to a file
            file1.writelines(L)
        with open('Sample_vt_collection.json','r') as f:
        #f = open("/Users/sonu/Sodin/myfile.json")
            data = json.loads(f.read())
            #for i in data['data']:            
            print(data['data']['attributes'])
        f.close() 
