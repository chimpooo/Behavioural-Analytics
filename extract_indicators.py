from numpy import append
import requests
import sys
import json
import pandas as pd
from requests.exceptions import HTTPError
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#extract the indicators from the virus total API and normalize the complex data
apikey = ''

def read_json(inputFile):
    with open(inputFile,'r', encoding='UTF-8') as json_file:
        data = json.load(json_file)
    return data

def write_json(inputData):
    with open('output.json', 'w') as outfile:
        json.dump(inputData, outfile)
    return True

def getBehaviour(file_hash):
    try:
        url=f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviours"
        headers = {'x-apikey': apikey,"Accept": "application/json"}
        response = requests.get(url,headers=headers)
    except:
        print("ERROR OCCURED")
    return response.json()

def getContactedIps(file_hash):
    url=f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_ips"
    headers = {'x-apikey': apikey,"Accept": "application/json"}
    response = requests.get(url,headers=headers)
    return response.json()

def getContactedUrls(file_hash):
    url=f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_urls"
    headers = {'x-apikey': apikey,"Accept": "application/json"}
    response = requests.get(url,headers=headers)
    return response.json()

def getDroppedFiles(file_hash):
    url=f"https://www.virustotal.com/api/v3/files/{file_hash}/dropped_files"
    headers = {'x-apikey': apikey,"Accept": "application/json"}
    response = requests.get(url,headers=headers)
    return response.json()

###### collections json files needs to be manually downloaded from VT
def getFilesFromCollection(collectionFile):
    data_json = read_json(collectionFile)
    return data_json['files']

def getdata(data_file):
    data_json = read_json(data_file)
    return data_json

def data_frame(data, field): 
    try: 
        if isinstance(data, dict):
            for k, v in data.items():
                if k == field:
                    header_label= k
                    '''ind = list(data.keys())
                    l= len(ind)
                    indi= list(data.items())
                    indx= ind.index(k)
                    print(indi[indx], '  ', indi[indx+1])'''
                    print(v)                                       
                elif isinstance(v, dict) or isinstance(v, list): 
                    data_frame(v,field)   
        elif isinstance(data, list):    
            for v in data:  
                data_frame(v,field)                           
    except (RuntimeError, TypeError, NameError):
        print(RuntimeError, TypeError, NameError)
    except:
        pass
    return None


#fileHash='0fa207940ea53e2b54a2b769d8ab033a6b2c5e08c78bf4d7dade79849960b54d'

##### USE DATA FROM JSON DURING DEVELOPMENT TO AVOID REACHING THE VT QUOTA LIMIT
# data = read_json('/Users/sonu/Sodin/myfile.json')
'''def data_frame(dataFile):
    #df=pd.DataFrame(dataFile.items())
    df=pd.DataFrame.from_dict(dataFile.items())
    return df'''

def get_values(data, field): 
    if(field is not None):
        res=""
        try: 
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == field:
                        '''ind = list(data.keys())
                        l= len(ind)
                        indi= list(data.items())
                        indx= ind.index(k)
                        print(indi[indx], '  ', indi[indx+1])'''
                        res=str(v)
                        break
                    elif isinstance(v, dict) or isinstance(v, list): 
                        res = str(get_values(v,field))  
                        if(res != ""):
                            break
            elif isinstance(data, list):    
                for v in data:  
                    res = str(get_values(v,field))
                    if(res != ""):
                            break                
        except (RuntimeError, TypeError, NameError):
            print(RuntimeError, TypeError, NameError)
        except:
            pass
    else:
        print("No data found")
    return res

def data_frame(data):
    dt=""
    try:
        if data is None:
            data="no data found"
            return dt
        else:
            #get the fields of the objects you want to access.
            dt= get_values(data, "id")+ ";"+ get_values(data, "verdicts") + ";"+ get_values(data, "meta") + ";"+ get_values(data,"registry_keys_set")+ ";"+ get_values(data,"mutexes_created") 

    except:
        print("other errors")
    return dt
    ############## get all indicators from files on files.json
    
def main():
    pass
    ############## get all behaviours from files on files.json
    data = {} #list of dictionaries
    final=''
    count=0
    files = getFilesFromCollection('files.json')  #list of file hashes
    df = pd.DataFrame()
    ds = pd.DataFrame()
    for file in files:
        d= getBehaviour(file) #get the behaviour of the file hash
        l=json.dumps(d)   
        with open("Sample_vt_collection.json", "w") as file1:
                    # Writing data to a file
            file1.writelines(l)
        with open("Sample_vt_collection.json", "r") as file1:
            json.loads(file1.read())      
        file1.close()
        dt=getdata('Sample_vt_collection.json')
        final= data_frame(dt)+('\n')+final
        
    #Collect the data for required indicators in a dataframe or csv format
    df = pd.DataFrame([x.split(';') for x in final.split('\n')], columns=['id','verdicts','meta','registry_keys_set','mutexes_created'])
    ds= df.to_csv('out.csv', sep=';', encoding='utf-8', index=False)
    print(ds)  
    print(df)   
if __name__ == "__main__":
    main()
