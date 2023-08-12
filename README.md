# Machine Learning Algorithms for Intrusion Detection

## Introduction

Machine learning algorithms play a crucial role in the field of network security, particularly in the detection of intrusions and attacks. There are three main categories of machine learning algorithms: supervised, unsupervised, and reinforcement learning. In this report, we focus on the application of two commonly used strategies, namely supervised and unsupervised learning.

Supervised learning is employed when we have a target variable to predict, while unsupervised learning is used in scenarios where the target variable is absent, and we aim to find similarities and patterns in the data. In this report, we use two models: K-means Clustering for unsupervised learning and Random Forest Classifier for supervised learning. Additionally, we explore the use of K-means Clustering as a supervised learning algorithm to evaluate its ability to classify attacks accurately.

## Dataset Analysis

### Data Collection

The dataset used for this analysis is the KDD CUP’99 dataset, a well-known benchmark for intrusion detection. This dataset contains a large number of connection records, each with 43 features extracted from DARPA tcpdump data. We focus on the 10% training subset of the data, consisting of 494,021 connection records and 22 attack types. The dataset includes a column named "target," which is used to create the target variable with 5 labels representing major attack categories.

### Data Insights

The dataset is rich and diverse, comprising various attributes, including fundamental properties, content, timely traffic, and host traffic properties. The 22 attack types are grouped into four major categories: Probe, DoS (Denial of Service), U2R (User-to-Root), and R2L (Remote-to-Local). We use this structured data to build models that can accurately detect these attack categories.

### Data Preprocessing

Before building the models, we perform essential data preprocessing steps. Categorical features like protocol_type, flag, and service are encoded, and the target variable ("Attack Type") is also encoded, particularly for K-means Clustering, which requires numerical values for clustering. We also standardize the features to ensure that they are on a consistent scale.

## Modeling and Results

### K-Means Clustering

K-means Clustering, a common algorithm for anomaly detection, is applied to the dataset. The Elbow Method is used to find the optimal number of clusters (K). Based on the analysis, K=3 is selected as the optimal value. However, when K-means Clustering is used for supervised learning, it fails to predict all five attack categories accurately, leading to partial success for three classes and accurate prediction for two.

![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/5488a4b1-a38f-4f7d-9621-57be34b9ca94)

![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/866114d4-5c6f-4243-934a-c5d0bc99c236)

![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/2fd19a5c-ef17-4ffb-9f7a-f6a0a968d4bd)

### Random Forest Classifier

To improve the accuracy of intrusion detection, we employ the Random Forest Classifier. This ensemble method demonstrates exceptional performance, achieving a high accuracy of 99.9% on both training and test datasets. The model shows a balanced ability to detect all five attack categories, with impressive F1-scores across most classes. Yellowbrick Library is used to visualize feature importance and learning curve.
![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/fc6f4d13-a3bd-47f5-9f0d-0fb53df1a280)

Yellowbrick library was used to create a confusion matrix for five classes.

![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/e4bd8caa-00a9-4946-82fc-9ba91783c985)

### Feature Importance

An essential aspect of the Random Forest Classifier is the feature importance analysis. We gain insights into which features contribute most significantly to the model's accuracy. This information can guide us in selecting relevant features when building future intrusion detection systems.
![image](https://github.com/tasawarz/Intrusion-Detection/assets/119436229/92283eb7-f96b-4cdd-82d0-420ea3141cd7)


## Conclusion

In this report, we explored the application of machine learning algorithms for network intrusion detection. While K-means Clustering, even when used as a supervised learning algorithm, fell short in predicting all attack categories accurately, the Random Forest Classifier achieved remarkable performance with high accuracy and F1-scores. The feature importance analysis provided valuable insights for feature selection in future models.

Overall, the Random Forest Classifier demonstrated its suitability for building an effective Intrusion Detection System, capable of accurately detecting various attack types, thereby enhancing network security. This report serves as a valuable contribution to the field of cybersecurity and machine learning-driven intrusion detection.
