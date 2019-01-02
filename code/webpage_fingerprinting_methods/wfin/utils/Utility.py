from __future__ import division
import numpy as np
from collections import defaultdict

# labelStringMap = { 'tol': 'total',
#     'max': 'maximum',
#     'min': 'minimum',
#     'mean': 'mean',
#     'median': 'median'  
# }

percentiles = [25, 50, 75, 90]

def roundToX(num, base):
    nnum = int(base * round(float(num)/base))
    return np.sign(num)*1 if nnum == 0 else nnum
    
def roundnumMarkers(num):
    if num==4 or num==5: return 3
    elif num==7 or num==8: return 6
    elif num==10 or num==11 or num==12 or num==13: return 9
    else: return num
    
def roundToPowerofX(num, X):
    if num == 0: 
        return 0
    return pow(X, round(np.log(num)/np.log(X)))

def getStatisticValue(dataArray, rValue = 1, Tol = True, Max = True, Min = True, Mean = True, Median = True, dev = True):
    results = defaultdict(float)
    if Tol: 
        results['tol'] = np.sum(dataArray) / rValue if len(dataArray) > 0 else 0
    if Max: 
        results['max'] = np.max(dataArray) / rValue if len(dataArray) > 0 else 0
    if Min: 
        results['min'] = np.min(dataArray) / rValue if len(dataArray) > 0 else 0
    if Mean: 
        results['mean'] = np.mean(dataArray) / rValue if len(dataArray) > 0 else 0
    if dev:
        results['dev'] = np.std(dataArray) if len(dataArray) > 0 else 0
    
    for percentile in percentiles:
        results[str(percentile) + 'Percentile'] = np.percentile(sorted(dataArray), percentile) / rValue if len(dataArray) > 0 else 0
    return results
    
def dsum(ret, *dicts):
    for d in dicts:
        for k, v in d.items():
            ret[k] = v
#     return ret

# Utility function to report best scores
def report(results, n_top=3):
    for i in range(1, n_top + 1):
        candidates = np.flatnonzero(results['rank_test_score'] == i)
        for candidate in candidates:
            print("Model with rank: {0}".format(i))
            print("Mean validation score: {0:.3f} (std: {1:.3f})".format(
                  results['mean_test_score'][candidate],
                  results['std_test_score'][candidate]))
            print("Parameters: {0}".format(results['params'][candidate]))
            print("")