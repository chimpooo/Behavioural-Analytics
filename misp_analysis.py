#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pymisp import PyMISP
import numpy as np
import re, json, requests
from levenshtein import calculate_distance, calculate_similarity, get_most_similar_in_list
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Correlate data in MISP and use Levenshtein for similarity
#Get indicators for Sodinokibi

class MISPhandler: 
    
    def __init__(self, misp_url, misp_key): 
        misp_verifycert = False      
        self.misp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
        
        # Get the attributes from MISP 
    def get_atributes_by_eventid(self) -> list:
       domain=[]
       vuln=[]
       substring = "virustotal"
       events=self.get_events()
       #print("MISP Events for Sodinokibi")
       for i in events:
              #misp_result = self.misp.search(eventid=[i], metadata=True, pythonify=True, controller='attributes', type_attribute='domain')
              misp_result = self.misp.search(eventid=[i], metadata=True, pythonify=True, controller='attributes')              
              #print("Event id: {}".format(i)+'\n')
              #print(misp_result)
              #domain.append('('+ format(i) +')')
              #print("Event extracted for following attributes:")
              for attr in misp_result:
                     #print(attr.value)
                if attr.type=="link":
                    if re.search(substring,attr.value):
                        print(i, attr.value)  #comparision between VirusTotal Samples and MISP
                if attr.type=="domain":
                    domain.append(attr.value)
                if attr.type=="vulnerability" and attr.value=="CVE-2018-8453":
                        #vuln[i]=attr.value
                    print(i,attr.value)
       #print(domain)
       Processed_domain=get_lists_for_leve(domain)
       #print(Processed_domain)
       return domain

       # Get the events from MISP  
    def get_events(self): 
       resp = self.misp.search(tags=['misp-galaxy:ransomware="Sodinokibi"'],pythonify=True)
       #resp = self.misp.search(tags=['Ransomware'],pythonify=True)
       events=[]
       for event in resp:
         events.append(event.id)
       return events


def get_lists_for_leve(data):
    THRESHOLD= 6
    tbr = {} # holds the index of the strings to be removed
    idx = 0
    for i in data:
        for j in range(len(data)):
            #if j != idx and calculate_distance(i, data[j]) < THRESHOLD:
            if j != idx and leve(i, data[j]) < THRESHOLD:
                tbr[j] = True
        idx += 1
    data1=[]
    data2 = []
    idx = -1
    for d in data:
        idx += 1
        if idx in tbr:
         data1.append(d)
         continue # skip this string
        data2.append(d)
    data1=list( dict.fromkeys(data1) )
    return data1

def leve(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    #print (matrix[-1,-1])
    return (matrix[size_x - 1, size_y - 1])


if __name__ == '__main__':
    
    misp_url = ''
    misp_key = ""
    misp_handler = MISPhandler(misp_url, misp_key)
    # Get event attributws  
    domains=misp_handler.get_atributes_by_eventid()
    #events=misp_handler.get_atributes_by_eventid()[0]
    Processed_domain=get_lists_for_leve(domains)
    print(Processed_domain)
    #print("Total events extracted: {}".format(len(misp_handler.get_events())))
    print(leve('charity-wallet.com', 'charity-wallt.com'))
'''    similar_domains=[]
    non_similar=[]
    for i in domains:
        for j in domains:
            threshold=calculate_distance(i,j)
            if threshold < 5 :
                similar_domains.append(j)
                print(i, j , threshold)
            else:
                non_similar.append(j)
    similar_domains=list( dict.fromkeys(similar_domains) )
    print(similar_domains)'''

    
    
