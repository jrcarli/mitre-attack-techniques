"""
Srapes MITRE's ATT&CK Groups
"""

from bs4 import BeautifulSoup
import requests
import pandas as pd

base_url = 'https://attack.mitre.org'
_groups = []
_techniques = {}
_software = {}

class Software(object):
    def __init__(self,title,url):
        self.title = title
        self.url = url
        self.techniques = []

class Technique(object):
    def __init__(self,title,url):
        self.title = title
        self.url = url

class Group(object):
    def __init__(self,title,url):
        self.title = title
        self.url = url
        # techniques is a list keys into the _techniques dict
        self.techniques = []
        # software is a list of titles, which are keys to the _sotware dict
        self.software = []

def getGroups():
    global _groups
    url = base_url + '/wiki/Groups'
    r = requests.get(url)
    if r.status_code != 200:
        print "Bad status (%d)"%(r.status_code)
        return 0
    
    soup = BeautifulSoup(r.text)

    group_td_list = soup.find_all('td',class_='Group')
    for g in group_td_list:
        a = g.find('a')
        link = a.get('href')
        title = a.string
        g = Group(title,link) 
        _groups.append(g)

    return len(_groups) 

def getSoftwareTechniques(sw_title):
    global _techniques, _software
    sw_techniques = []
    if sw_title not in _software:
        return
    sw = _software[sw_title]
    url = base_url + sw.url
    r = requests.get(url)
    if r.status_code != 200:
        print "Bad status (%d) in getSoftwareTechniques"%(r.status_code)
        return
    start_str = '<span class="mw-headline" id="Techniques_Used">'
    end_str = '<span class="mw-headline" id="Groups">Groups</span>'
    start = r.text.find(start_str)
    end = r.text.find(end_str, start)
    techniques_section = r.text[start:end]
    soup = BeautifulSoup(techniques_section)
    a_tags = soup.find_all('a')
    # we only care about a tags that have a title attribute
    for a in a_tags:
        if 'title' not in a.attrs:
            continue
        # Create Technique if first encounter 
        if a.string not in _techniques:
            t = Technique(a.string, a.get('href'))
            _techniques[a.string] = t
        sw_techniques.append(a.string)
    return sw_techniques

def getTechniquesAndSoftware(group):
    global _techniques, _software
    url = base_url + group.url
    r = requests.get(url)
    if r.status_code != 200:
        print "Bad status (%d)"%(r.status_code)
        return

    # This doesn't present Techniques Used in a common div or other structure
    start_str = '<span class="mw-headline" id="Techniques_Used">Techniques Used</span>'
    end_str = '<span class="mw-headline" id="Software">Software</span>'
    start = r.text.find(start_str)
    end = r.text.find(end_str, start)
    techniques_section = r.text[start:end]
    soup = BeautifulSoup(techniques_section)
    a_tags = soup.find_all('a')
    # we only care about a tags that have a title attribute
    for a in a_tags:
        if 'title' not in a.attrs:
            continue
        # Create Technique if first encounter 
        if a.string not in _techniques:
            t = Technique(a.string, a.get('href'))
            _techniques[a.string] = t
        # Create link to Technique within this Group
        group.techniques.append(a.string)

    # Now get the software
    start_str = '<span class="mw-headline" id="Software">Software</span>'
    end_str = '<h2 id="References">References</h2>'
    start = r.text.find(start_str)
    end = r.text.find(end_str, start)
    software_section = r.text[start:end]
    soup = BeautifulSoup(software_section)
    a_tags = soup.find_all('a')
    for a in a_tags:
        sw = a.string
        # Create Software if first encounter
        if sw not in _software:
            s = Software(sw,a.get('href'))
            _software[a.string] = s
        # Create link to Software within this Group
        group.software.append(sw)

        # Update this Group's techniques based on Software
        sw_techniques = getSoftwareTechniques(sw)
        #for t in sw_techniques:
        #    group.techniques.append(t)
        group.techniques.extend(sw_techniques)
    #group.techniques.extend(sw_techniques)
    group.techniques = list(set(group.techniques))

def main():
    global _groups
    num_groups = getGroups()
    print "Found %d groups"%(num_groups)

    group_list = []
    technique_list = []

    # Collect the entire set of Techniques and Software
    for group in _groups:
        #print "%s:\t%s"%(group.title,group.url)
        getTechniquesAndSoftware(group)
        #print "Techniques:"
        for t in group.techniques:
            #print "\t%s"%(t)
            group_list.append(group.title)
            technique_list.append(t)
   
    df = pd.DataFrame({'Group':group_list,
                       'Technique':technique_list}) 
    df.to_csv('attack_group_technique.csv',index=False,encoding='utf-8')

if __name__=='__main__':
    main()
