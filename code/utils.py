import json, pickle

def load_json(file_path):
    with open(file_path) as f:
        return json.load(f)
    
def dump_json(o, file_path):
    with open(file_path,"w") as f:
        return json.dump(o, f)
    
def dump_pickle(o, file_path):
    with open(file_path, "wb") as f:
        pickle.dump(o, f)
        
def load_pickle(file_path):
    with open(file_path, "rb") as f:
        return pickle.load(f)
    
    
host_label = {
    'investor.vanguard.com': "Vanguard",
    'www.aclu.org': "ACLU",
    'www.legalzoom.com': "Legal\nZoom",
    'www.mayoclinic.org': "Mayo\nClinic",
    'www.plannedparenthood.org': "Planned\nParenthood",
    'www.wellsfargo.com': "Wells\nFargo",
    'www.bankofamerica.com': "Bank of\nAmerica",
}