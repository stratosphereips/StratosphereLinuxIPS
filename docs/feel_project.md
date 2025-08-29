# Federated Learning for ML


## Methodology

### Proposed Solution

We use horizontal cross-device federated learning for detecting malicious
activity in encrypted TLS network traffic. Cross-device in this context means,
that the clients represent edge computers, monitoring and capturing their
traffic. It is horizontal because the clients observe the same set of features,
produced by different entities. The federated approach allows to distributively
train a model using the client’s observations, without having direct access to
the data. This enables us to protect the privacy of the data, while still being
able to learn from it. In addition, each client also benefits from cooperative
training, as they use a global detection model that is averaged from all model
updates sent by all the clients. The global model, therefore, had access to a
larger and more diverse set of data coming from all clients, possibly leading
to better performance and generalization, compared to a model trained only
with each client’s local data.



###  Solution Architecture
Our federated learning system consists of a central aggregator and multiple
clients. The aggregator is a dedicated machine that initializes and coordinates
the training process. There are ten clients in our system, representing the
edge computers, each containing their data in the form of processed feature
vectors used for training the detection models. The data spans multiple
days, and each day is treated as a separate training process. The clients
split each day’s data into training and validation data using an 80/20 split.
The clients use the data of the next day as testing data for the current day.
This is functionally equivalent to training the model on yesterday’s data and
evaluating it on today’s data as it is coming in.
At the start of the training, every client needs to adjust its features to a
common range. For this purpose, they each fit a MinMax scaler, which finds

![image](https://github.com/user-attachments/assets/25ca7237-ede8-459d-b08d-57fdbc78d55a)

Figure: Diagram of the training process. Each day is treated as a separate
training process with multiple federated training rounds. The aggregator co-
ordinates the training process, distributes the global models, and creates new
models using updates it receives from the clients. The clients distributively
train the models using their local data. In our work, there are up to ten clients
participating in the training.

the minimum and maximum values of every feature in the client’s training data.
Those extreme values are then shared with the aggregator, which combines
them to produce a global MinMax scaler that is then distributed back to the
clients. We choose the MinMax scaler, as it can be easily implemented in the
federated setting. This scaler traditionally scales the values to 0-1 range. It
is possible that some of the values transformed by the scaler may lay outside
the fitted range of the scaler, as the scaler fit on the training data is also used
to transform the validation and testing data. In this case, the values will be
scaled outside of the 0-1 range proportionally to the values observed in the
training data. This does not create issues for our work, as the used features
are computed on 1-hour windows and are mostly consistent.
The training itself is initiated by the clients receiving an initial global
model from the aggregator. The clients then train this model for a series
of rounds. A round consists of the clients training the models locally for
a number of epochs specified by the aggregator. After the local training,
each client reports how the model’s weights changed to the aggregator. In
turn, the clients receive an updated aggregated global model, which they
use in the next round. For the purposes of the experimental evaluation, the
clients also evaluate the new aggregated global model on their testing data,
which consists of the benign and malicious from the next day. They compute
relevant metrics on this dataset and report them back to the aggregator.
After which the next round of training starts.
The number of rounds and local epochs depends on the complexity of the
models and the number of training iterations it needs to converge. Increasing
the number of local epochs means that the model can be trained for the same
number of epochs while decreasing the number of rounds. This effectively
lowers the communication overhead. However, more local iterations may also

lead to a higher risk of divergence of the models, as the clients receive the
global models less often. We discuss the exact number of rounds and local
epochs in the following sections describing the individual approaches.
The aggregator combines metrics using a weighted average with the number
of clients’ samples as weights. It also produces a global model after each
round using a process described in  Learning Algorithm Section. At the end of the day’s
training process, the aggregator selects the best-performing model using an
aggregated validation loss of each model. This model is used as the initial
model for the next day. We assume that when the model is reused, it can
be trained for fewer rounds as it already possesses some domain knowledge.
This can save on both computational and communication resources as well as
enable the model to preserve previous knowledge.


#### Unsupervised Approach

For unsupervised learning, we use a Variational Autoencoder (VAE) to detect
anomalies in the network traffic. One reason for using unsupervised learning,
in this case, is that it might be difficult to obtain high-quality labels for
malware traffic, which are needed for supervised learning approaches. Although
our dataset is labeled, previous works have reported that unsupervised
learning can be effective for detecting anomalies in network traffic data.
The anomaly detection model consists of an encoder and a decoder. The
encoder of the model embeds the inputs into a 10-dimensional latent space.
It fits multivariate normal distributions (with a diagonal covariance matrix)
from the data to generate the embedded samples. The decoder then attempts
to reconstruct the input vector from its compressed representation. The
architecture of the model is shown in the Implementation Decisions section.
The model is trained using a combined loss function consisting of the reconstruction
loss Lmse (Mean Square Error of the input and output vectors), and
the regularization Kullback-Leibler loss (KL), which penalizes the difference
between the learned distribution and the standard normal distribution. The
use of this penalty function was introduced together with the VAE, and
ensures that the learned distributions do not diverge from each other and
[produce a generalizing embedding](https://arxiv.org/abs/1312.6114).
The loss function for each sample can
be represented as:

![image](https://github.com/user-attachments/assets/460d2681-9736-4dc4-9f6b-86f99965dd02)


![image](https://github.com/user-attachments/assets/31678f02-4570-4467-a125-9d8653963589)

Figure: Architecture of the Neural Network models used in this work. The
Classifier-only model is derived from the Multi-Head model by removing its
reconstruction head.

For detection, the reconstruction loss is used as an anomalous likelihood.
Each client derives an anomaly threshold based on its validation data. The
reconstruction error on the normal data is often used for deriving the anomaly
threshold. The clients compute reconstruction errors for every sample
in their normal validation dataset. From those values, they found a threshold
that classifies 1 % of their validation data as malicious. We use this approach
in order to provide robustness to outliers in the benign validation data. If we
would instead choose the maximum value on the validation dataset, it could
select some non-malicious outlier of the dataset. Such a threshold would then
result in more malware being missed. The specific value of 1% was chosen
using an expert heuristic.

After computing individual thresholds, the clients send them back to the
aggregator, which averages them and weights them by the ratio of the training
data in each client to produce a global threshold. On the first day, when the
model is trained from scratch, ten training rounds are used, and five when
the model from the previous day is reused. Clients train the model locally for
one epoch in the first two rounds and for two epochs in the remaining rounds.
While more local rounds are more communication efficient, it may also lead to divergence in the individual client’s
updates. When using the momentum-based methods, the largest steps in the
parameter space are generally made in the first few epochs
[produce a generalizing embedding](https://arxiv.org/abs/1312.6114). We hope
that by aggregating after each epoch in the first two rounds, the global model
manages to converge into a state from which it reliably converges with less
frequent aggregations.



#### Supervised Approach

For supervised learning, we use two types of models, a Multi-Head model
and a Classifier-only model. They are shown in the Figures in the Implementation
Decisions section. The Multi-Head model is derived from a regular autoencoder by
adding a classification head after the encoder while also keeping the decoder
part. We hope that by keeping the autoencoder components, the clients with
only benign samples can contribute to the learning process by improving the
embedding space. The model is trained to distinguish malicious traffic from
benign; malicious being the positive class. Only benign samples are passed
to the decoder part of the network so that the network does not learn to
reconstruct the malicious samples well.

![image](https://github.com/user-attachments/assets/1ddffcfb-0774-463d-a0c0-1f09e2c22ca3)



The Classifier-only model was created to evaluate if the decoder part of
the Multi-Head model brings any benefits. Its structure is identical to the
Multi-Head model, but with the reconstruction part of the network missing.
This effectively turns it into a regular classification model and is trained using
only the Binary cross entropy.
The supervised models are trained for 75 rounds on the first day when
the models are trained from scratch. On the following days, when the model
from the previous day is reused, 25 training rounds are used. Clients train
the model locally for one epoch every round.


#### Malware Vaccine
The motivation behind the Multi-Head model is to allow all clients to participate in supervised training, even if they do not have any malware data.
However, it was observed that having clients participating without positive
samples makes the supervised federated model unable to converge. To address
this, we decided to send each client a set of malicious feature vectors, which
we call a "vaccine", to help with the convergence. Traditionally in the security
field, vaccines are a harmless part of the malware that is injected into the
host machines [to prevent infections](https://ieeexplore.ieee.org/document/6468401). Our vaccines differ in that they are
not a passive mechanism but an aid in the learning process and a way to
tackle data heterogeneity, as suggested [here](https://arxiv.org/abs/1912.04977)
in [the Dataset Section](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/docs/feel_project.md#dataset).
The vaccines are comprised of only numerical values and, as such, do not pose any risk to the
clients. In our setting, the central aggregator is responsible for gathering and
distributing this set of data to the clients. This approach could be achieved in
real deployments by using samples of malicious network traffic from publicly
available datasets. In order to mitigate the convergence issues, the "vaccine"
dataset has to be sufficiently large (more than 70 feature vectors).

#### Assumptions and Limitations
In this subsection, we discuss the assumptions and limitations of our work.

- Supervised learning assumption: In the supervised setting, we
assume that the clients have the capability to label the data locally. This
is a relatively strong assumption in real deployments, but our work aims
at developing methods that would only require this from a subset of the
participants.
- Unsupervised learning assumption: For the unsupervised setting,
we assume that there are no malicious samples in the benign dataset.
While we are confident that this assumption holds in this work, as the
dataset was created using expert knowledge, it may be challenging to
assure in future work or in real-world deployments.
- Client trust: We also assume that the clients who connect are not
malicious and try to damage the training process or extract knowledge
from other clients.
- Client availability: One limitation of our work is that we do not handle
cases where some clients drop out or are unavailable during the training
process. Although this is quite common in real-world settings, we believe
that with the limited size of the dataset, we would not be able to evaluate
this well.


Overall, our work has several assumptions and limitations that should be
considered when interpreting the results and implications. These limitations
do not invalidate our findings, but they should be taken into account when
considering the generalizability and applicability of our approach.


#### Learning Algorithm
To train our models, we use a combination of FedAdam and FedProx
algorithms. SGD with FedProx regularization is used to train the models in
the clients. FedProx adds a term to the loss function penalizing the clients’
divergence from the last received global model. This mitigates divergence in
case of statistical differences between the clients’ datasets. This client-side
regularization is important when training with a small batch size (making
a larger number of local steps) or when training locally for multiple epochs
before sending the weight updates to the aggregator.
On the server side, the clients’ contributions are aggregated using a weighted
average based on the amount of clients’ training data. Using this aggregate,
a new update to the global model is created using the FedAdam algorithm
provided in the flower framework. It is a federated variant of the Adam
optimizer, and as such, it uses momentum when aggregating the client
updates providing better convergence on the heterogenic data.


#### Implementation Decisions
We chose to use a Python-based open-source federated learning framework
called [Flower](https://arxiv.org/abs/2007.14390) to implement our methods. Flower is a versatile framework
that provides extendable implementations of both the server (aggregator)
and the clients. It is designed to handle the communication between the
aggregator and clients, enabling us to focus on developing the methods. In
addition, Flower includes implementations of some of the common algorithms
for aggregating client updates.
In the Flower framework the user is responsible for implementing the
functionality, such as loading the local dataset, orchestrating the local fitting,
and computing the metrics. To train the models in the clients, we have used
TensorFlow in combination with Keras. On the server side, the
aggregation of metrics must be implemented, as well as the initialization of
the model and setting of training parameters. Flower allows for the sending of
serializable data structures, which can be useful for exchanging configurations
or other information between aggregator and clients. The serializable data
has been used to distribute the vaccines from the aggregator to the clients.

The code for this work can be found in the repository of the FEEL project:
https://github.com/stratosphereips/feel_project. This repository contains the implementation of the described methodology, including the code
for orchestrating and running experiments and analyzing their results. It also
includes the preprocessing of raw data into hourly feature vectors used by
the models. The feature extraction is based on an in part reused from the
work done [by František Střasák](https://dspace.cvut.cz/bitstream/handle/10467/68528/F3-BP-2017-Strasak-Frantisek-strasak_thesis_2017.pdf).



## Testing

### Experiment Setup
This section describes how the proposed methods are evaluated, how they
are compared, and how the metrics are collected.
For the purposes of this work, one experiment is a set of conditions and
parameters which are evaluated. Each experiment consists of ten federated
runs with identical parameters, differing only in the random seed used for
initializing the model and splitting the local datasets for training and valida-
tion. Each run in an experiment performs a federated run, a local run, and a
centralized run; all using the same parameters and random seed.
On each run, the models are trained for a total of four days, producing a
global detection model each day. These models are then evaluated on the
next day’s data resulting in four sets of evaluation metrics from each of the
runs. Only four days are evaluated because the dataset has five days and the
last day can not be evaluated since there is no next day.

#### Federated Training Process
The dataset on which our solution is evaluated has network traffic from
five consecutive days for ten distinct clients. Only five clients have labeled
malicious traffic which can be used for supervised training, the rest five clients
only have benign traffic.
On each day a federated training process is done. The diagram in the Architecture section
illustrates the federated training process. On the first day of training, the
model is initialized randomly and trained from scratch on each client’s data,
while on the following days (days 2, 3 and 4), the previous day’s model is
reused. On a given day, the clients train using data from that day, split into
training and validation data (using an 80/20 split). The validation dataset is
used for selecting the best-performing global model (based on an aggregated
validation loss). The testing is done on the next day’s traffic, which is
functionally equivalent to using the previous day’s model for detection.
The model from the previous day is used, so that gained knowledge from
the past is preserved while also not requiring the clients to keep data for
longer periods of time. In general, when training the model from scratch,
more rounds of training are necessary than when adjusting an already existing
model to newer data.

####  Metrics
After each round, the clients evaluate the received global model on their test
dataset by computing a set of metrics. Each of these values is aggregated
on the server using a weighted average, where the weights are relative ratios
of the sizes of clients’ data used for generating the metrics. Meaning, that
in the case of testing metrics, the sizes of the test datasets were used, with
the vaccine samples included. The motivation for this is to produce similar
metrics as if they were computed on a complete dataset from all clients.
To evaluate our methods, the metrics used are Accuracy (Acc), True
Positive Rate (TPR), False Positive Rate (FPR) shown in eqs. (2.1) to (2.3)
and F-score shown in eq. (2.5). Accuracy is a standard metric used to
evaluate classification and detection models. However, it can not capture
all the relevant information on its own. TPR indicates what ratio of the
malicious samples was detected, and FPR shows how much of the benign
samples are misclassified as malicious. The F-score is often advocated as a
summarizing metric when comparing the performance of two classifiers.
We use its unweighted variant F1.


#### Comparison to Other Settings
All experiments are repeated ten times with a different random seed for
initializing the model and splitting the dataset. Each run of the federated
experiment is accompanied by training the same model with equivalent
parameters in a local and centralized setting.

- Local setting: The local setting mimics the scenario when the client
decides not to participate in the federated learning and instead creates a
model using only its data. Comparing this to the federated results should
show the benefits of joining the federated process. When evaluating the
local setting, we use the datasets of all clients for the following day. This
is to demonstrate how well the locally trained models would perform
in other clients or when encountering unknown threats. The reported results
 are averages of the performance the models.
- Centralized setting: the Centralized setting represents a case where
there would be no restrictions on the privacy of the data so that we
could collect all datasets of the clients into a single one and use that
for training the models. This should provide an ideal scenario for the
model’s performance.


---

### Dataset

For the evaluation of the proposed solution, we have considered existing
datasets used by researchers studying network security. However, Federated
Learning requires that the used dataset can be split in a specific manner to
represent the local datasets of the individual participants of the federated
process. Therefore a dataset for Federated Learning should include several
different clients and possibly different days. Moreover, the split between classes
should be realistic in the sense that its parts should be non-IID, meaning they
should have different sizes, class balances, and the statistical distribution of
the feature differ. Although some federated datasets in network security exist,
they are mostly based on IoT malware, which is not complex and relatively
easy to detect. IoT malware also usually does not use HTTPS traffic. We
therefore decided to use [the CTU-50-FEEL dataset]( https:
//zenodo.org/record/7515406) created for this research.
CTU-50-FEEL is a dataset that contains very specific HTTPS features
based on the more generic dataset CTU-50 created by [the Stratosphere
Laboratory](https://www.stratosphereips.org/).
CTU-50-FEEL consists of aggregated features for ten clients that generate
traffic for five days. All the clients produce benign traffic, but only five of
them also produce malware traffic mixed with the benign. The dataset also
contains a sixth malware for testing. The following sections describe the
process of creation, processing and subsequent feature extraction.
In particular for this research, the CTU-50-FEEL dataset was further modified to create a dataset variation called CTU-50-FEEL-less-malware. This
variant contains much less malware per client, and less clients with malware,
and therefore is much harder to detect. This was done to further test our
supervised methods. More details about the differences between the variants
is shown in the Dataset Mixing Section.

#### Benign Traffic
The CTU-50-FEEL dataset has the traffic of 10 real human users (no simula-
tions) over five consecutive days. The original format of the flows uses the
Zeek logs to form the dataset. [Zeek](https://zeek.org/) is an open-source tool for monitoring
and analyzing network traffic. It saves the network events into log files based
on their type. The conn.log contains records about each connection, such
as the used protocol, the originator, and the responder, as well as a unique
identifier of the connection, which can be used to associate it with other types
of logs. The ssl.log and x509.log log files are also relevant for this work, as they
contain information about HTTPS connections and the certificate used to
establish the encrypted connection. Zeek can generate other types of logs for
different types of traffic or protocols, but those that are not used for feature
extraction. All flows in the log files were labeled using the Stratosphere Lab’s
tool [netflowlabeler](https://github.com/stratosphereips/netflowlabeler).


The following Table shows the number of TLS flows per client for each day. The traffic
comes from real users, which are active for different periods each day and
are using different operating systems and sets of applications. This results in
realistic traffic where there are significant differences in the client data. The
10 real users used Linux, Windows and macOS operating systems.
The benign dataset was created by capturing the traffic of users in
Stratosphere Laboratory. The traffic was collected with their consent and for
the purposes of security research. The CTU-50-FEEL dataset only consists
of processed aggregated numerical features and does not contain any Zeek
flow data or identifiable information.


![image](https://github.com/user-attachments/assets/7dea91f4-0be1-4367-8eeb-33e5e6505ac4)


#### Malware Traffic
The malicious traffic comes from the deployment of real malware in the
Stratosphere Laboratory. All malware use TLS for command and control
communication. As this traffic is encrypted, it is more difficult to distinguish
it from normal traffic. The following table shows the number of TLS flows of each
malware on individual days. The number of malware flows is much lower
than the benign traffic, and two of them have TLS activity only on the first
day.

![image](https://github.com/user-attachments/assets/cf6d9d42-a27a-4692-8afd-30ff7f8a62bf)

#### Feature Extraction
To train neural network models on the data, we need to extract numerical
features from the data. For that, we took advantage of the work done by
František Strašák [here](https://dspace.cvut.cz/bitstream/handle/10467/68528/F3-BP-2017-Strasak-Frantisek-strasak_thesis_2017.pdf. The methodology used allows us to extract useful
and proven features from TLS data to detect threats. However, in our work,
we have decided to aggregate the traffic in one-hour windows, instead of
per-day. This enables faster detection of possible threats, as the feature
vectors and subsequent detection can be done within an hour of capturing
the traffic.
Within the one-hour window, connections are aggregated based on a 4-tuple
of source IP address, destination IP address, destination port, and protocol.
This 4-tuple allows to group all related connections to one specific service.
The flows inside the 4-tuple share a unique purpose and behavior. These
values, along with information about the amount of data transferred and
some temporal aspects of the connection, are extracted from the conn.log
files. Features relating to the TLS traffic are computed from the values
contained in ssl.log files using the certificate information located in the
x509.log files. The complete list of features can be seen in the following Table. Features
mentioned as not used in the table were omitted because of low variance in
their values. Both benign and malware data were processed in this manner.
The processed dataset without the identifying information can be found at:
https://github.com/stratosphereips/feel_data

![image](https://github.com/user-attachments/assets/de337742-57b4-4cc5-a14a-a18415c871cc)


#### Dataset Mixing
For the purpose of this work, we needed to mix the malware and benign
traffic to form a supervised dataset. For the CTU-50-FEEL dataset, we have
achieved that by assigning a different malware to each the first six clients.
Two of the malware only had some HTTPS activity on the first day. This
mixing was designed to fully utilize all captured malware traffic. The total
number of feature vectors for each client can be seen in the following table.
In the Supervised Approach Section we described the malware vaccine which is a set feature
vectors from the malware dataset, which is sent to the clients to improve the
convergence of the supervised federated methods. On each day we dedicated
one day of a malware datasets to be used as a vaccine. Which malware
dataset is used as a vaccine for a given day is shown in the following table. When the
clients receive the vaccines, they incorporate them into their local dataset
and use them to train the supervised models.


![image](https://github.com/user-attachments/assets/5f6c0d30-f682-417b-894d-a5c8afbd8c01)



We also designed a scenario that enables us to assess how the proposed
methods cope with more complicated setups. We have named this variant
of the dataset CTU-50-FEEL-less-malware. Its benign data is identical to
the CTU-50-FEEL, but we have removed malware infection on some of the
days. The overview of the malware left in the CTU-50-FEEL-less-malware
in each client is shown in the following table. Note that the syntax M<malware
number>-<day> references the malware captured by a client in the complete
mix on a particular day. The table also indicates which vaccine was used
each day.

Table: The used malware in the CTU-50-FEEL-less-malware dataset for
each client. The M<malware number>-<day> references a particular day of
malware from the malicious data of CTU-50-FEEL. Benign
data is identical to CTU-50-FEEL, as shown in the next Table.


Decreasing the number of malware present in the clients leads to increased
class imbalance and amplifies the overall non-IID properties of the clients’
datasets. While in the CTU-50-FEEL, around half of the clients did have
some malware traffic on each day, in this variant, the number of infected
clients at a given time is even smaller. By designing this more challenging
scenario, we hope to demonstrate the capabilities of the developed methods
to handle the following challenges:

- Challenge one: The situation where on the first day only the "vaccine"
malware is present, with some malware appearing on the second day
in some of the clients. As the models are evaluated on the next day’s
data, it test how well it is able to generalize from one type of malware
to others, as well as how well the models can adapt to new malware
appearing.

![image](https://github.com/user-attachments/assets/6a0fdd29-5d62-4839-870d-3a8ce773fb28)


- Challenge two: The situation where on the third and fourth days, malware
that was previously used as a vaccine reappears after not being present
on the previous day. This evaluates how well the knowledge is preserved
 after retraining on a different set of threats
- Challenge three: The situation where the last day contains all available
malware to test the final model on as much malicious data as possible.

![image](https://github.com/user-attachments/assets/64d3aee6-d5a5-43c9-b65a-f4a07397299e)

### Experiments
This section describes the experiments conducted to evaluate the methods
proposed in the Methodology chapter using the dataset described
in [the Dataset Section](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/docs/feel_project.md#dataset).
We provide a description of the parameters used when running the experiments and an
the results.


#### Unsupervised Experiments
Recall that the unsupervised experiments are designed to measure how well
FL can be used for clients without labels for their traffic. In these experiments,
we use the Autoencoder architecture described in the Unsupervised Approach
Section for anomaly detection. Each client trains the model using its benign local data of a
particular day according to the CTU-50-FEEL dataset. The data for that
day is split into training and validation datasets using an 80-20 split (80%
for training).
The validation data is used for selecting the anomalous threshold. Each
client selects as threshold a 99 percentile of their validation losses, i.e. value,
which will mark 1 % of their validation samples as anomalous. The thresholds
on each client are then weighted on the aggregator based on the number of
training samples in the clients and finally averaged to produce the global
detection threshold. The aggregator uses the combined weighted validation
loss to selecting the best-performing model. By default, the model is saved
and reused on the next day’s training.
If the model is trained from scratch, it is trained for ten rounds. If the
model from the previous day is re-used, then it is only trained for five rounds.
The model is trained at the clients for one epoch in the first two rounds and for
two epochs for the remaining rounds. The batch size used is 64. Both global
and local learning rates are set to 10−3 and the first and second momentums
of FedAdam are set to 0.9 and 0.99 respectively. The μ parameter of the
proximal term is set to 10.

One run of the experiment consists of training on the first four days and
always testing on the next day’s dataset. Each run is repeated ten times with a
different random seed, with the values reported in this section corresponding
to the mean values across the runs. Each run of the experiment is also
accompanied by a centralized and local run.

##### Experiment A1: Reusing the model on the next day
This type of experiment reuses the previous day’s model on each next day.
This allows for fewer training rounds on the subsequent days as well as
preserving knowledge from across the days, as the model is effectively exposed
to a larger amount of data.
Figure (a) shows results of these type of experiments. When the model is
trained in the federated setting, it outperforms the models trained locally in
almost every metric, while the centralized models achieve better results than
both of them.
Although on some days the local models detect marginally more malicious
samples, their average False Positive Rate is almost one and a half that of
the federated one. This results in significantly better accuracy and F1 for
the federated model.
Although it is expected that a centralized model would perform better
due to access to all data simultaneously, these results show that clients using
the federated model would anyway greatly benefit from participating in the
federated learning. This shows that federated learning can be a valuable
alternative when direct data sharing is not feasible or desired.


##### Experiment A2: New model on each day
In contrast to experiments A1, it is important to evaluate the effects of
training a new model completely each day. This requires training for the
whole ten rounds each day and therefore can mitigate the degradation of the
model.
The summarized results in the following table show that training a model from
scratch every day marginally but marginally improves the performance. This
may hint that the performance of the reused model is degrading, which
seems to be the case for testing days 3 and 4 according to the results in
Appendix A.1. However, on the final day, the A1 model outperforms the
A2 model. An explanation for this observation might be a change in the
distribution of the clients’ benign data between day 4 (the training day) and
day 5 (testing day). [Table 5.5](https://private-user-images.githubusercontent.com/41242896/396211886-6a0fdd29-5d62-4839-870d-3a8ce773fb28.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQzNzI4NjMsIm5iZiI6MTczNDM3MjU2MywicGF0aCI6Ii80MTI0Mjg5Ni8zOTYyMTE4ODYtNmEwZmRkMjktNWQ2Mi00ODM5LTg3MGQtM2E4Y2U3NzNmYjI4LnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTYlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE2VDE4MDkyM1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWIyNWVkN2E1MzJmOWUxMzJhMGZlNjZmOTQ2MTE3ZDU0ZmEyNWUwYTFiMWJjZmNlMWY1YjI5YjM5ZTY0NTc0MDQmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.cbO4FpCfhA3nz4hiassakG8tc0Z4dcJeCGgc_EN_aE8)
shows the differences in amounts of benign
data between these days. Possibly the A1 model may be more resilient after
multiple rounds of fine-tuning.

![image](https://github.com/user-attachments/assets/41e26b88-c8f4-4bc8-8e22-a00bdea62b15)


Table: Summary of the anomaly detection experiments. The provided values
are averages over the four testing days with ten runs each.


##### Experiments A3: Effect of fewer participants
In previous type of experiments A1 and A2 all ten clients always participated
in the training. In this type of experiment, we evaluate the performance of
models when only training on six and three of the original clients, while still
evaluating using the complete next day’s dataset.
As expected, with the decreased number of clients used for training, the
obtained models perform worse. However, the gap between the centralized
and federated models increases significantly with the decreased number of
participants. Analogically, this could mean that with more clients, the
performance gap between centralized and federated could shrink.

#### Supervised Experiments
Recall that the supervised experiments are designed to use the knowledge
and labels in the clients, independently of how these labels were obtained. In
the supervised setting, some clients have malicious samples in addition to
benign samples. The distribution of the malware dataset among the clients is
described in the Dataset Mixing section. Most of the parameters of the training remained
unchanged from the unsupervised experiments, except of the number of
training rounds which we increased to 75 if training the model from scratch

and to 25 if reusing the model from the previous day. In this set of experiments,
each client trains the models for one epoch each round. The vaccine used for
the supervised experiments is described in the Dataset Mixing section.
Two types of architectures are evaluated - the Multi-Head model with both
a classification head and a decoder head and a Classifier-only model. As with
unsupervised cases, each experiment is run in a federated, centralized, and
global setting and is repeated ten times with a different random seed.

##### Experiment S1: CTU-50-FEEL dataset and reusing the model
This scenario represents the base case for the supervised experiments. The
benign and malicious datasets of the CTU-50-FEEL are split amongst the 10
clients. In this scenario, every client is used for both training and evaluation.
The summarized results are shown in the Table 5.2 in
[the Supervised Experiments Section](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/develop/docs/feel_project.md#supervised-experiments),
and the breakdown of the performance on individual days can be seen in [this Figure](https://private-user-images.githubusercontent.com/41242896/396213092-bf251463-b17d-4058-9748-d1976745086f.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQzNzI4NjMsIm5iZiI6MTczNDM3MjU2MywicGF0aCI6Ii80MTI0Mjg5Ni8zOTYyMTMwOTItYmYyNTE0NjMtYjE3ZC00MDU4LTk3NDgtZDE5NzY3NDUwODZmLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTYlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE2VDE4MDkyM1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPThkZmZiNmYyZDU5MDVkYTFlZTczNWZhOWE5OTM1OTQ5OTQyZWI0MjdiMTMxNDJjNTMzNjA2YWJkYjM2Y2E0M2MmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.HGiNAPQ-qcMEElcEAIm3Y7WjjdPkeHEEyo8fccCpgIs).
The figure also compares the performance of supervised models to that of the anomaly
detection model. As expected, the supervised models achieve much better
results, and even the locally trained supervised models outperform centralized
AD models. Most of the improvements come from improved recall (TPR).
Previously it hovered below 50%, but the supervised models reached nearly
100% recall meaning almost all malware samples are detected.
The two variants of the supervised models reach comparable results, with
the Classifier-only model achieving marginally better average accuracy and
F1 metrics. However, the performance margin is minor and does not provide
enough evidence to claim the superiority of one of the model variances.
Compared to the unsupervised models, both classifying variants come
closer to the performance of the centralized model event outperforming it in
some metrics. However, the relative gap between local and federated settings
increased compared to the AD model. This is likely caused by some of the
clients only containing benign data, and all malicious samples used in training
originate from the vaccine.

##### Experiment S2: Only training the model using clients
with malicious data
In experiments of type S1 all clients are used for federated training of the
model even if the client does not possess any malicious samples. In order
to evaluate if their inclusion brings any benefit to the final model, the S2
experiment is designed in which clients non-infected clients are excluded from
training and only used for evaluation. Specifically, Clients 1-6 are used to
train on the Day 1 and Clients 1, 2, 4, 6 on the following days, as clients 3,
and 5 only have malware data on the first day.
The summary results of the S2 experiments are shown in the below Table. Al-
though the number of training clients decreased, the models managed to
preserve a similar performance to those of S1. In the federated setting, the
only observable difference is a statistically insignificant improvement in the
Multi-Head models’s F1 and a similarly inconclusive decrease of the same
metric of the Classifier-only model.
A more pronounced difference is in the TPR of the local models, which
improved when trained only on the clients with their own malware. This
supports the claim from the previous subsection that when training locally,
using malicious data only from the vaccine results in worse performance.
![image](https://github.com/user-attachments/assets/65935bb5-eec6-4f43-9956-c683bef212ff)

Table: Summary of the S1, S2, and S3 experiments all conducted on the
CTU-50-FEEL dataset. The provided values are averages over the 4 testing
days.

##### Experiment S3: New model on each day
In the S1 and S2 scenarios, we save the model at the end of training to
be reused on the next day. This saves computational and communication
resources since the reused models can be trained for fewer epochs. It might
also enable the model to remember threats it saw on previous days and
transfer this knowledge into the future.
However, there is also a risk of gradual degradation of the model and worse
adaptability to shifting distribution of data. In this type of experiments, we
train a new model every day to measure the impacts of these potential risks.
The summary of results in [this Table](https://private-user-images.githubusercontent.com/41242896/396212878-65935bb5-eec6-4f43-9956-c683bef212ff.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQzNzI4NjMsIm5iZiI6MTczNDM3MjU2MywicGF0aCI6Ii80MTI0Mjg5Ni8zOTYyMTI4NzgtNjU5MzViYjUtZWVjNi00ZjQzLTk5NTYtYzY4M2JlZjIxMmZmLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTYlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE2VDE4MDkyM1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWJhNWU4NjU5YzdiYWE0ZWFkZTA1M2IxNTI2ZWUwMzIxNTFhNTI5ZGRhNDA0NDY4ZjFiYTIwYjdkY2RkN2NkOTkmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.KdKZIS9HoqmcbYyiukcoJxhu2cEZzI-1FZScTYuSa68)
shows that while the performance of
the Multi-Head S3 model is comparable to the S1 type, the S3 Classifier-
only models’s average TPR is much lower with higher variance. The detailed
results in Table A.5 show that on the first testing day the model performs the
same as the other models, and only on the following days it degrade. Since
the first training day contains the most malicious samples, it suggests that
the Classifier-only model needs more positive samples in the clients.
The similar performance of the Multi-Head model in the S1 and S3 experi-
ments suggests that reusing the model does not lead to degraded performance
over time while requiring fewer training rounds.



##### Experiment S4: Using the CTU-50-FEEL-less-malware dataset
the Dataset Mixing section describes a second type of malware mix which we have created in
order to test our proposed models. CTU-50-FEEL-less-malware is designed
to be both more challenging and more realistic by including less positive class
samples. None of the clients have any malware data on the first day and have
to rely on the vaccine provided by the aggregator to train the classification
model. In the following days, only two to three clients have their own malware
samples, and the final day, which is only used for evaluation, contains as
much malware as possible. As the amount of malware and its types change
every day, it should prove to be much more challenging for the model and its
ability to adapt.
[Figure (a)](https://private-user-images.githubusercontent.com/41242896/396213461-12083155-f834-44b2-a0ae-0481a3d651e1.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MzQzNzI4NjMsIm5iZiI6MTczNDM3MjU2MywicGF0aCI6Ii80MTI0Mjg5Ni8zOTYyMTM0NjEtMTIwODMxNTUtZjgzNC00NGIyLWEwYWUtMDQ4MWEzZDY1MWUxLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDEyMTYlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQxMjE2VDE4MDkyM1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWQ0MjRiYzNkM2I4MmZkZWE1Y2U3ZGFjYjFjNDczOTVlNDhmN2Q3NTcxMWU4MWYyYTY0Mjk0YmE1MjkxNmI2MDImWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.6LbCo9FlKWiVCvxMPqE8PFfaAnyAxmCv4AumJKEOHaM) presenting the results of this experiment shows that this scenario
is much more challenging for the supervised methods. Although the overall
accuracy is still higher than in the unsupervised experiments, there are
measurable differences between the two classification models.
Day 2 results are produced by models trained only on the first day when no
client has any malware data except the vaccine. However, on the second day
on which the model is tested, two different malware are present in the client’s
dataset, which the model struggle to detect. The third day contains the same
malware as the first day’s vaccine (M4) and the traffic of M6 malware, which
is the same type as the M1 present on the second day. This results in overall
better performance on Day 3.
On the following day, the M2 appears in Client 2 while only being used
as a vaccine on Day 2 previously. However, it seems that the model was not
able to preserve its knowledge well since the true positive rate decreased on
that day. The final day is only used for testing and contains a larger amount
of malware samples. Despite that, the models perform best on it with an
average F1 score above 90%.
This more challenging data scenario shows that with small amounts of
positive samples, the models might struggle to converge to a solution that is
able to detect the malware. When the models are trained with only the benign
data and the vaccine, it occasionally resulted in models which did not mark
any of the test samples as malicious. This seems to affect the Multi-Head
model more than the Classifier-only model. Although on the next day, all of
the Classifier-only models mostly recovered, some of the Multi-Head ones still
performed significantly worse. This effect seems to disappear in the following
days.

##### Experiment S3+S4: New model on each day,
CTU-50-FEEL-less-malware dataset
The CTU-50-FEEL-less-malware dataset variant also provides a good setting
to test, how well the model preserves information from previous days. In the
scenario, there are instances where a dataset is used for training on one day,
is not present on the next day, and reappears on one of the following ones. In
order to evaluate if the reuse of the model brings any benefits in these cases,
we combined the S4 data scenario and S3 in which the model is trained from
scratch each day.
The results are shown in Figure (b). Day 2’s results are not really relevant
as the setting is functionally identical to the S4 experiment. The differences
in the results on this are given by some of the models failing to converge to a
solution that is able to detect any malware. Similar issues can be observed
on Day 3. It seems that reusing the model can mitigate it, as all of the S4
models are detecting at least some malware.
On Day 4, when more clients have malware, all models converged to a
working state. However, the average recall of the Classifier-only model is
significantly worse than that of the Multi-Head model and both of the models
which reused models from previous days.
The last testing day with the highest amount of malware data again shows
a worse performance of the Classifier-only model. When comparing the S4
and S3+S4 Multi-Head model outperforms its variant, which reuses the model
from the previous day. There is also a much smaller variance in the results


Overall, this more difficult data scenario shows that with fewer malicious
samples in the clients’ datasets, both evaluated supervised models face issues
with convergence. In multiple cases, the models converged to local minima,
where they classified every sample as benign. However, when reusing the
model from the previous day, the model is able to recover from it.
A shortcoming of the supervised methods is that it relies on the clients to
label their data correctly and also to be infected to have malicious samples. In
feature works, we would like to investigate a setting in which the aggregator
provides bigger and more diverse vaccines as a form of threat intelligence, and
Federated Learning would be used as a means to learn from clients’ benign
data. This approach would mitigate privacy concerns while taking advantage
of public malware datasets created by the security community.
In this work, the models are always learning from a single day of network
traffic. As having access to more training data at once is generally better, we
would evaluate how the models would benefit from being trained on longer
spans of activity. However, this might require a new dataset containing data
for more days. While we did not observe any degradation in the performance
of the models when they were reused for multiple days, it would be beneficial
to test whether this holds for longer deployments. It would also be interesting
to investigate whether the models need to be periodically retrained from
scratch to maintain their performance. A longer dataset would be useful for
this purpose.

![image](https://github.com/user-attachments/assets/bf251463-b17d-4058-9748-d1976745086f)


Figure: Comparison of the three types of models on the A1 (for unsupervised)
and S1 (supervised) scenarios. The models trained on the CTU-50-FEEL dataset,
split amongst ten clients. The days refer to the days on which the models were
tested, being trained on the previous day. At the end of the day’s training, the
model was saved to be reused the next day.
![image](https://github.com/user-attachments/assets/12083155-f834-44b2-a0ae-0481a3d651e1)

Figure: Results of the supervised models on a CTU-50-FEEL-less-malware
dataset. The models were trained from scratch each day in the S4+S3 experiment
and the previous day’s model was reused in the S4 experiment.

##### Detailed results


##### Detailed results

![image](https://github.com/user-attachments/assets/e7ee2952-1472-4d39-89a0-8bd50e9fa62b)
![image](https://github.com/user-attachments/assets/97745f8a-7cce-488d-96d3-f45afd5e9bd5)
![image](https://github.com/user-attachments/assets/4e8c1131-2c80-45ae-9b89-255cc9e79599)
![image](https://github.com/user-attachments/assets/d90499f5-65e0-46bb-84e4-3c7be55b4c22)



---

Our results showed that federated-trained models consistently outperformed
those trained solely on local data. While centralizing data can often produce
the most accurate models, it is not always possible due to technical limitations,
privacy concerns, or legal requirements. In these cases, Federated Learning
offers a way to train effective malware detection models while taking these
considerations into account.
We evaluated the models on a series of training and testing days to somehow
mimic an actual real deployment and the challenges related to it. In particular
the challenge of how the distribution of data may shift between individual
days. The datasets used in this work reflect this well, as the benign traffic
was collected from actual users using different operating systems and sets of
applications with notable differences in activity in the span of the five days.
One way to handle the situation of different distribution of data is to
train a new model for each day, which ensures that the daily models are
independent and do not suffer from degraded performance due to changes in
data distribution.


The experiments were successful in showing that the models from the
previous day could be reused, and its training could be resumed on a new
day of data. This leads to lower computational and communication overhead,
as fewer training rounds were necessary to adapt the model to new data than
to train it from scratch. This approach also has the potential to enable the
model to remember threats or types of data it encountered in the past. We
attempted to evaluate the long-term memory capabilities of the model, but
we did not observe any significant improvements in this aspect when reusing
the model.
Obtaining reliable labels in the network security setting can be difficult as it
usually requires deep domain knowledge from the user. To address this issue,
we have developed a fully unsupervised method for detecting threats in the
client’s traffic. This method uses a variational auto-encoder and utilizes it for
anomaly detection. The model is trained on a dataset of benign data, which
allows it to learn the distribution of normal network traffic. By comparing
new data to this distribution, the model can identify data that is unusual
or out of the ordinary and mark it as potentially malicious. However, our
experiments showed that this method was not always able to accurately detect
all types of malware, as some of it was indistinguishable from normal traffic
for the model.


To take advantage of labels, we also run supervised methods of detection.
In this setting, we assume that only a subset of clients was able to observe
the malicious activity. Having malicious samples only in some clients make
the setting more realistic, as in the real world, it is unlikely that every client
would be infected. That also means that the non-infected clients only have
training samples of one class. Including these clients in the federated training
process often results in the models not converging correctly and learning the
trivial classification of marking every sample as benign. Although we were
successful in addressing these convergence issues, it is clear that this is a
particularly challenging aspect of Federated Learning.
The solution to this problem was to introduce the concept of "vaccine".
A vaccine, for us, is a set of malicious data which is distributed to the
clients, which would incorporate it into their own local dataset and use it for
training. It is the responsibility of the aggregator to obtain this set of data by,
for example, capturing the traffic of malware, processing it, and extracting
features. These features can be safely distributed among the clients, as they
are purely numerical and do not contain any of the malware’s actual traffic
or code. We have shown that when utilizing vaccines, the supervised models
are able to converge to a state in which they accurately detect a majority of
the malware. However, our experiments also showed that occasionally when
the amount of malicious data available to the clients is small (for example,
only the vaccine), the models may still fail to converge properly. In these
cases, we suggest implementing a fallback system that would automatically
restart the training process with a differently initialized model.
In the supervised experiments, we have evaluated two types of models: a
Multi-Head model and a Classifier-only model. The Multi-Head model was
trained on two tasks:
- reconstructing an input feature vector similar to an autoencoder
- classification of the traffic.

The Classifier-only model was derived from the Multi-Head model by discarding the reconstruction
part of the network. The rationale behind training the Multi-Head model on
two tasks is that even clients with mostly benign data can contribute to the
learning by improving the embedding of the model.
Our experiments showed that the simpler Classifier-only model achieves
better results. However, in scenarios with fewer malicious samples, we were
observed the convergence issues more often in the case of Classifier-only
model than in the case of Multi-Head model.

---

## Community Adoption of the Federated Learning for ML

Slips and FEEL projects were showcased at the following conferences, where attendees were invited to share our project and provide feedback.

- [2023 Slips BlackHat Europe 2023 Arsenal. ](https://www.youtube.com/watch?v=FHJCN8eWtEw&ab_channel=StratosphereIPS)
- [2023 Slips BlackHat Asia 2023 Arsenal. ](https://www.youtube.com/watch?v=HyNvf8pCIlQ&t=1s&ab_channel=StratosphereIPS)
- [2024 Slips BlackHat Asia 2024 Arsenal. ](https://www.youtube.com/watch?v=j9IPFZHiuTA&t=1s&ab_channel=StratosphereIPS)
