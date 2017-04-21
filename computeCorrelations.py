# -*- coding: utf-8 -*-
"""
Created on Fri Apr 21 09:47:59 2017

@author: sofiasilva
"""
from scipy.stats.stats import pearsonr
import pickle

issuesPercentagesPickle = './issuesPercentages.pkl'
creationAgesPickle = './creationAges.pkl'
lastModAgesPickle = './lastModAges.pkl'
allocAgesPickle = './allocAges.pkl'

issuesPercentages = pickle.load(open(issuesPercentagesPickle, "rb"))
creationAges = pickle.load(open(creationAgesPickle, "rb"))
lastModifiedAges = pickle.load(open(lastModAgesPickle, "rb"))
allocationAges = pickle.load(open(allocAgesPickle, "rb"))

corr_creationAge, p_value_creationAge = pearsonr(issuesPercentages, creationAges)
print 'Correlation between percentage of reverse delegations with issues and the creation date: Correlation coefficient: {}; p-value: {}'.format(corr_creationAge, p_value_creationAge)

corr_lastModAge, p_value_lastModAge = pearsonr(issuesPercentages, lastModifiedAges)
print 'Correlation between percentage of reverse delegations with issues and the last modified date: Correlation coefficient: {}; p-value: {}'.format(corr_lastModAge, p_value_lastModAge)

corr_allocAge, p_value_allocAge = pearsonr(issuesPercentages, allocationAges)
print 'Correlation between percentage of reverse delegations with issues and the date of allocation: Correlation coefficient: {}; p-value: {}'.format(corr_allocAge, p_value_allocAge)
