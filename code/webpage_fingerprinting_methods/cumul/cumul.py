from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from collections import Counter
import pickle
from multiprocessing import Pool
import json
import numpy
import sys
import os
import numpy
import itertools
from sklearn.svm import SVC
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import GridSearchCV

from sklearn.preprocessing import StandardScaler
from sklearn import preprocessing
from sklearn.pipeline import Pipeline
from collections import Counter
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import LabelEncoder

class Cumul():
    @classmethod
    def get_name(cls):
        return "CUMUL"
    
    def get_cumul_features(self, packet_sizes):
        #authors' implementation
        features = []
        
        total = []
        cum = []
        pos = []
        neg = []
        inSize = 0
        outSize = 0
        inCount = 0
        outCount = 0
        for packetsize in packet_sizes:
            if packetsize > 0:
                inSize += packetsize
                inCount += 1
                # cumulated packetsizes
                if len(cum) == 0:
                    cum.append(packetsize)
                    total.append(packetsize)
                    pos.append(packetsize)
                    neg.append(0)
                else:
                    cum.append(cum[-1] + packetsize)
                    total.append(total[-1] + abs(packetsize))
                    pos.append(pos[-1] + packetsize)
                    neg.append(neg[-1] + 0)

            # outgoing packets
            if packetsize < 0:
                outSize += abs(packetsize)
                outCount += 1
                if len(cum) == 0:
                    cum.append(packetsize)
                    total.append(abs(packetsize))
                    pos.append(0)
                    neg.append(abs(packetsize))
                else:
                    cum.append(cum[-1] + packetsize)
                    total.append(total[-1] + abs(packetsize))
                    pos.append(pos[-1] + 0)
                    neg.append(neg[-1] + abs(packetsize))

        # add feature
#         features.append(classLabel)
        features.append(inCount)
        features.append(outCount)
        features.append(outSize)
        features.append(inSize)
        
        featureCount = 100
        cumFeatures = numpy.interp(numpy.linspace(total[0], total[-1], featureCount+1), total, cum)
        for el in itertools.islice(cumFeatures, 1, None):
            features.append(el)
            
        return features
    
    
    def get_x(self, visit_file):
        with open(visit_file) as f:
            visit = json.load(f)
            
        packets = []
        for connection in visit['tcp_connections']:
            for packet in connection['packets']:
                packets.append(packet)

        packets.sort(key=lambda packet: packet[0])
        packet_sizes = []

        for packet in packets:
            if not packet[1]:
                continue
            packet_sizes.append(packet[1])
            
        features = self.get_cumul_features(packet_sizes)
        return features
    
    def get_x_all(self, visit_files, n_cpu):
        with Pool(n_cpu) as pool:
            return list(pool.map(self.get_x, visit_files))
        
    def tune_parameters_and_get_score(self, train_x, train_y, test_x, test_y, n_cpu, output_dir):
        pipeline = Pipeline([
            ('scale', StandardScaler()),
            ('classify', SVC(probability=True))
        ])
        
        param_grid = [
            {
                'classify__C': [2**i for i in range(11,17)],
                'classify__gamma': [2**i for i in range(-3,3)]
            }
        ]
                        
        cv = StratifiedShuffleSplit(n_splits=2, test_size=0.2, random_state=1)
        
        #error_score=0 : Value to assign to the score if an error occurs in estimator fitting
        grid = GridSearchCV(pipeline, param_grid=param_grid, n_jobs=n_cpu, refit=True, error_score=0,verbose=0)
        grid.fit(train_x, train_y)
        print("The best parameters are %s with a score of %0.2f"
              % (grid.best_params_, grid.best_score_))  
        
        probabilities = grid.predict_proba(test_x)
        probabilities_file = os.path.join(output_dir,"probabilities.txt")
        with open(probabilities_file,"w") as f:
            f.write("labels {}\n".format(" ".join(map(lambda x: str(int(x)), sorted(set(train_y))))))
            for i, label in enumerate(test_y):
                f.write("{} {}\n".format(int(label), " ".join(map(lambda x: str(x), probabilities[i]))))
                
        return grid.score(test_x, test_y)
    
    def get_score(self, train_x, train_y, test_x, test_y, n_cpu, output_dir):
        pipeline = Pipeline([
            ('scale', StandardScaler()),
            ('classify', SVC(C=2**22, gamma=2**4))
        ])
        print("get_score")
        pipeline.fit(train_x, train_y)      
        return pipeline.score(test_x, test_y)
           
    def classify(self, train_visit_files, test_visit_files, visit_file_label, output_dir, n_cpu):
        train_x = self.get_x_all(train_visit_files, n_cpu)
        train_y = list([visit_file_label[x] for x in train_visit_files])
        
        test_x = self.get_x_all(test_visit_files, n_cpu)
        test_y = list([visit_file_label[x] for x in test_visit_files])
        
        score = self.tune_parameters_and_get_score(train_x, train_y, test_x, test_y, n_cpu, output_dir)
#         score = self.get_score(train_x, train_y, test_x, test_y, n_cpu, output_dir)
        return score