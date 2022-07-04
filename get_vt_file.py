
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
endpont_get_report_hash = "https://www.virustotal.com/api/v3/files/{0}"
#endpont_get_report_hash = "https://www.virustotal.com/api/v3/collections/{0}"



def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.

#curl --request GET --url https://www.virustotal.com/api/v3/files/84f909f2a044110a830148d98d47351342a2f1c9d5f75e6b8801ff34c9e9fa98 --header 'x-apikey: ----'


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
if __name__ == '__main__':
    print_hi('Malware')
    print("--------------------------------------X-------------------------------------X")
    print("\n")
    virus_total = requests.Session()
    header_request = {"x-apikey": virustotal_apikey}
    list_malwares = get_malware_url_names()
    for current_malware in list_malwares:
        if current_malware is not None:
            print("malware info", current_malware )
            #response_report_hash = virus_total.get(endpont_get_report_hash.format(hash_test),headers=header_request, proxies=proxies, verify=verify_ssl)
            response_report_hash = virus_total.get(endpont_get_report_hash.format(current_malware),headers=header_request, proxies=proxies, verify=verify_ssl)
            print(response_report_hash)
            L = response_report_hash.text
            # Writing to file
            with open("/Users/sonu/Sodin/myfile.json", "w") as file1:
                # Writing data to a file
                file1.writelines(L)
            with open('/Users/sonu/Sodin/myfile.json','r') as f:
            #f = open("/Users/sonu/Sodin/myfile.json")
                data = json.loads(f.read())
                #for i in data['data']:            
                print(data['data']['attributes'])
            f.close() 

   
    ###########
    ## analysis logic
    ## could be mapped into a table like colums[hash(string),command_execution(list),verdicts(list)..]

# print(len(data['data']))
# print(type(data['data'][0]))
# print((data['links']))
# print((data['data'][0]).keys())
# print((data['data'][0]['attributes']).keys())
# print(len(data['data']))
# print((data['data'][0]['type']))
# print((data['data'][0]['id']))
# print((data['data'][0]['links']))
# print(data['data'][0]['attributes']['command_executions'])
# print(data['data'][0]['attributes']['verdicts'])
# print(data['data'][0]['attributes']['processes_created'])
# print(data['data'][0]['attributes']['registry_keys_set'])
# print(data['data'][0]['attributes']['has_pcap'])
# print(data['data'][0]['attributes']['mutexes_opened'])
# print(data['data'][0]['attributes']['analysis_date'])
# print(data['data'][0]['attributes']['sandbox_name'])
# print(data['data'][0]['attributes']['has_html_report'])
# print(data['data'][0]['attributes']['registry_keys_deleted'])
# print(data['data'][0]['attributes']['behash'])
# print(data['data'][0]['attributes']['has_evtx'])
# print(data['data'][0]['attributes']['last_modification_date'])
# print(data['data'][0]['attributes']['has_memdump'])
# print(data['data'][0]['attributes']['mutexes_created'])
# print(data['data'][0]['attributes']['processes_tree'])
# print(data['data'][0]['attributes']['modules_loaded'])

