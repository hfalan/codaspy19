import pickle
featuresFilePath = "/nas/longleaf/home/juneyan/fs_data/results/tmp/FeatureFiles"
analyzePath = '/nas/longleaf/home/juneyan/fs_data/results/tmp/EvaluationResults'

testnum = 2
trainingnum = 14
w_TOP = 775
JVM_MEMORY_SIZE = '4192m'
WEKA_JAR = '/nas/longleaf/home/juneyan/fs_data/weka-3-8-0/weka.jar'
L1DistanceThreshold = 0.3
n_open_train = 3500

#countermeasures
countermeasures = ['', "PadToMTU", "PadPacketRand", "PadSessionRand", "PadLinear", "PadExponential", "PadMiceElephant", "PadPacketRandomMTU", "trafficMorphing", "directTargetSampling"]
Padding = ["PadToMTU", "PadPacketRand", "PadSessionRand", "PadLinear", "PadExponential", "PadMiceElephant", "PadPacketRandomMTU"]
classifiers = ['Herrmann', 'Liberator', 'Panchenko',  'VNG']
selfDefinedClassifiers = ['Burst', 'Html', 'Packet', 'Tamarraw', 'TCP', 'Time', 'Port']

slabel = ['tol', 'max', 'min', 'mean', 'median']

cMap = {0: 'NoCountermeasures',
        1: 'PadToMTU',
        2: 'PadPacketRand',
        3: 'PadSessionRand',
        4: 'PadLinear',
        5: 'PadExponential',
        6: 'PadMiceElephant',
        7: 'PadPacketRandomMTU',
        8: 'directTargetSampling',
        9: 'trafficMorphing',
       11: 'BuFLO'}

CToId = {'NoCountermeasures': 0,
         'PadExponential': 5,
         'PadLinear': 4,
         'PadMiceElephant': 6,
         'PadPacketRand': 2,
         'PadPacketRandomMTU': 7,
         'PadSessionRand': 3,
         'PadToMTU': 1,
         'directTargetSampling': 8,
         'trafficMorphing': 9,
          'BuFLO':11}