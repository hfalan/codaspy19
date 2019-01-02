
import os
import sys
cur_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(cur_dir,"utils"))
import dataset_new as dataset
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from collections import Counter
import pickle
from multiprocessing import Pool
import json

from sklearn.ensemble import RandomForestClassifier
from multiprocessing import Pool
import json
import glob
import os
import Config
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import ExtraTreesClassifier
import tld
from sklearn.svm import LinearSVC
from sklearn.feature_selection import SelectFromModel, RFECV
from sklearn.ensemble import ExtraTreesClassifier
import numpy as np
from collections import defaultdict
import pickle
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import RandomizedSearchCV

def get_tld(hostname):
    top_level_hostname = tld.get_tld(hostname, fix_protocol=True, fail_silently=True)
    return top_level_hostname if top_level_hostname else "unknown"

class Wfin():
    @classmethod
    def get_name(cls):
        return "Wfin"
    
    def __init__(self):
        self.server_addresses = set()
        self.host_names = set()
    
    def get_features(self, visit_file):
        Config.hostname = dict()
        features = dataset.get_features(visit_file, SERVER_ADDRESS=self.server_addresses, HOST_NAMES=self.host_names)        
        return features
    
    def get_features_all(self, visit_files, n_cpu):
        with Pool(n_cpu) as pool:
            return list(pool.map(self.get_features, visit_files, chunksize=1))
        
        
    
    def get_host_names_and_server_addresses(self, visit_file):
        with open(visit_file) as f:
            visit = json.load(f)
            
        server_addresses = set(visit['ip_to_name'].keys())
        host_names = set(visit['ip_to_name'].values())
        return server_addresses, host_names
            
    def determine_host_names_and_server_address(self, visit_files, n_cpu):
        with Pool(n_cpu) as pool:
            for server_addresses, host_names in list(pool.map(self.get_host_names_and_server_addresses, visit_files)):
                self.server_addresses |= server_addresses
                self.host_names |= set(map(get_tld, host_names))
            
    def classify(self, train_visit_files, test_visit_files, visit_file_label, output_dir, n_cpu):
        print("determine host names2")
        print(len(train_visit_files), len(test_visit_files))
        self.determine_host_names_and_server_address(train_visit_files, n_cpu)
#         print(len(self.server_addresses), list(self.server_addresses)[:5])
#         print(len(self.host_names), list(self.host_names)[:5])


        print("extract training features")
        train_x = self.get_features_all(train_visit_files, n_cpu)
        train_y = list([visit_file_label[x] for x in train_visit_files])
        
        print("extract test features")
        test_x = self.get_features_all(test_visit_files, n_cpu)
        test_y = list([visit_file_label[x] for x in test_visit_files])
        
        print("fitting 600")
        pipeline = Pipeline([
            ('vectorize', DictVectorizer()),
#             ("classify", ExtraTreesClassifier(n_jobs=n_cpu, n_estimators=2000, min_samples_leaf=4))
            ("classify", ExtraTreesClassifier(n_jobs=n_cpu, n_estimators=1000))
        ])
        pipeline.fit(train_x, train_y)
        
        
        
        clf = pipeline.named_steps['classify']
        importances = clf.feature_importances_
        std = np.std([tree.feature_importances_ for tree in clf.estimators_],
                     axis=0)
        indices = np.argsort(importances)[::-1]
        
        feature_names = pipeline.named_steps['vectorize'].feature_names_
        with open(os.path.join(output_dir, "feature_names.pickle"),"wb") as f:
            pickle.dump(list(feature_names), f)
            
        print("num features:", len(feature_names))
        
        f_importance = defaultdict(float)
        for i in indices:
            f_importance[feature_names[i].split("*")[0]]+=importances[i]
            
        print("dump feature importance")
        print(output_dir)
        with open(os.path.join(output_dir, "feature_importance.pickle"),"wb") as f:
            pickle.dump(f_importance, f)
            
        for k, v in sorted(f_importance.items(), key=lambda x: x[1],reverse=True)[:5]:
            print(k, v)
        
        
        score = pipeline.score(test_x, test_y)
        
        try:
            probabilities = pipeline.predict_proba(test_x)
            probabilities_file = os.path.join(output_dir,"probabilities.txt")
            with open(probabilities_file,"w") as f:
                f.write("labels {}\n".format(" ".join(map(lambda x: str(int(x)), pipeline.named_steps['classify'].classes_))))
                for i, label in enumerate(test_y):
                    f.write("{} {}\n".format(int(label), " ".join(map(lambda x: str(x), probabilities[i]))))
        except Exception as e:
            print(e)
            pass
                   

        return score